# /// script
# requires-python = ">=3.14"
# dependencies = [
#     "jinja2>=3.1.6",
#     "pydantic>=2.13.5",
#     "pyyaml>=6.0.3",
#     "typer>=0.27.1",
# ]
# ///

import io
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Final, override

import typer
import yaml
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from pydantic import BaseModel, StringConstraints

SCRIPT_DIR: Final[Path] = Path(__file__).resolve().parent
TEMPLATES_DIR: Final[Path] = SCRIPT_DIR / "templates"

OLD_DIR_NAME: Final[str] = "old"
NEW_DIR_NAME: Final[str] = "new"

SIGNATURES_DIR_NAME: Final[str] = "signatures"
CONTROL_DIR_NAME: Final[str] = "control"
DATA_DIR_NAME: Final[str] = "data"

PKGINFO_FILE_NAME: Final[str] = ".PKGINFO"
MELANGE_CONFIG_FILE_NAME: Final[str] = ".melange.yaml"

PKGINFO_FILE_PATH: Final[Path] = Path(CONTROL_DIR_NAME) / PKGINFO_FILE_NAME
MELANGE_CONFIG_FILE_PATH: Final[Path] = (
    Path(CONTROL_DIR_NAME) / MELANGE_CONFIG_FILE_NAME
)

# 8-15 = log_2(window_size)
# 16   = decode gzip stream only
# 32   = decode zlib or gzip stream
ZLIB_WBITS: Final[int] = zlib.MAX_WBITS | 16

# Read in chunks of 1MiB
READ_CHUNK_SIZE: Final[int] = 1024 * 1024


class MelangeConfig(BaseModel):
    environment: MelangeConfigEnvironment


class MelangeConfigEnvironment(BaseModel):
    contents: MelangeConfigEnvironmentContents


# A string in the format "package=version"
type PackageVersionEntry = Annotated[str, StringConstraints(pattern=r"^[^=]+=[^=]+$")]


class MelangeConfigEnvironmentContents(BaseModel):
    repositories: list[str]
    keyring: list[str]
    packages: list[PackageVersionEntry]


@dataclass(frozen=True, slots=True)
class SliceBounds:
    offset: int
    length: int


class FileSlice(io.RawIOBase):
    """
    A file-like object that only lets you read a slice of a wrapped file-like object.

    This can help you only read a single section of a file made up of multiple concatenated sections.
    e.g. an Alpine Package Keeper (.apk) file.
    """

    __file: Final[io.RawIOBase]
    __slice_bounds: Final[SliceBounds]

    __pos: int

    @override
    def __init__(self, file: io.RawIOBase, slice_bounds: SliceBounds) -> None:
        super().__init__()
        if not file.readable:
            raise ValueError("File must be readable")

        if not file.seekable:
            raise ValueError("File must be seekable")

        file.seek(slice_bounds.offset, io.SEEK_SET)

        self.__file = file
        self.__slice_bounds = slice_bounds
        self.__pos = 0

    @override
    def readable(self) -> bool:
        return True

    @override
    def seekable(self) -> bool:
        return True

    @override
    def seek(self, offset, whence=io.SEEK_SET, /) -> int:
        match whence:
            case io.SEEK_SET:
                new_pos = offset
            case io.SEEK_CUR:
                new_pos = self.__pos + offset
            case io.SEEK_END:
                new_pos = self.__slice_bounds.length + offset
            case _:
                raise ValueError("invalid whence")

        self.__pos = max(0, min(new_pos, self.__slice_bounds.length))

        self.__file.seek(self.__slice_bounds.offset + self.__pos)

        return self.__pos

    @override
    def readinto(self, buffer, /):
        remaining_len = self.__slice_bounds.length - self.__pos
        if remaining_len <= 0:
            return 0

        output_buffer = memoryview(buffer).cast("B")

        try_read_len = min(len(output_buffer), remaining_len)

        actual_read_len = self.__file.readinto(output_buffer[:try_read_len])

        self.__pos += actual_read_len

        return actual_read_len

    @override
    def tell(self) -> int:
        return self.__pos


def split_gzip_streams(file_path: Path) -> list[SliceBounds]:
    """
    Read through a sequence of concatenated gzip streams to find where they
    start and end.
    """
    slices: list[SliceBounds] = []

    slice_offset = 0
    pos = 0

    d = zlib.decompressobj(wbits=ZLIB_WBITS)

    with open(file_path, "rb") as f:
        while True:
            buffer = f.read(READ_CHUNK_SIZE)
            if len(buffer) == 0:
                break

            while len(buffer) > 0:
                # Decompress the buffer, throwing away the decompressed output
                d.decompress(buffer)

                if d.eof:
                    pos += len(buffer) - len(d.unused_data)

                    slice_bounds = SliceBounds(
                        offset=slice_offset,
                        length=pos - slice_offset,
                    )
                    slices.append(slice_bounds)

                    # Save the unused data for the next stream
                    buffer = d.unused_data

                    slice_offset = pos

                    # Reset the decompressor
                    d = zlib.decompressobj(wbits=ZLIB_WBITS)
                elif len(d.unconsumed_tail) > 0:
                    # We did not consume all the data in the buffer (we hit the output buffer max_length)
                    pos += len(buffer) - len(d.unconsumed_tail)
                    buffer = d.unconsumed_tail
                else:
                    # We have consumed all the data in the buffer
                    pos += len(buffer)
                    buffer = b""

    return slices


def extract_apk(apk_path: Path, output_dir: Path) -> None:
    """
    Extract an Alpine Package Keeper file.

    This splits the output into separate subdirectories corresponding to the
    signature, control, and data sections of the .apk.
    """

    sigs_dir = output_dir / SIGNATURES_DIR_NAME
    control_dir = output_dir / CONTROL_DIR_NAME
    data_dir = output_dir / DATA_DIR_NAME

    sigs_dir.mkdir(parents=True, exist_ok=True)
    control_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)

    streams = split_gzip_streams(apk_path)

    control_idx = len(streams) - 2
    data_idx = len(streams) - 1

    for idx, stream_bounds in enumerate(streams):
        with (
            tarfile.open(
                fileobj=io.BufferedReader(
                    FileSlice(open(apk_path, mode="rb", buffering=0), stream_bounds)
                )
            ) as tar,
        ):
            if idx == control_idx:
                tar.extractall(control_dir, filter="tar")
            elif idx == data_idx:
                tar.extractall(data_dir, filter="tar")
            else:
                tar.extractall(sigs_dir, filter="tar")


def strip_pkginfo_commit(pkginfo_data: str) -> str:
    """
    Replace the "commit" field of a .PKGINFO with a static value

    :return: The stripped .PKGINFO data
    """

    return re.sub(
        r"^commit = .+$",
        "commit = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        pkginfo_data,
        flags=re.MULTILINE,
    )


def strip_pkginfo_pkgver(pkginfo_data: str) -> str:
    """
    Replace the "pkgver" field of a .PKGINFO with a static value

    :return: The stripped .PKGINFO data
    """
    match = re.search(r"^pkgver = (.+)$", pkginfo_data, flags=re.MULTILINE)

    if match is None:
        print("::error::Could not find pkgver in .PKGINFO file")
        sys.exit(1)

    version = match.group(1)

    return pkginfo_data.replace(version, "xxxxxxxxxx")


def diff_pkginfo(
    old_pkginfo: Path,
    new_pkginfo: Path,
    output: Path,
    strip_commit=True,
    strip_pkgver=False,
) -> bool:
    old_pkginfo_data = old_pkginfo.read_text(encoding="utf-8")
    new_pkginfo_data = new_pkginfo.read_text(encoding="utf-8")

    if strip_commit:
        # We don't want to compare the "commit" field of the .PKGINFO files.
        # The commit could change for various reasons that do not affect the output
        # package data, so we strip it out
        old_pkginfo_data = strip_pkginfo_commit(old_pkginfo_data)
        new_pkginfo_data = strip_pkginfo_commit(new_pkginfo_data)

    if strip_pkgver:
        # We don't want to compare the "pkgver" field of the .PKGINFO files.
        # If we are comparing releases *we know* that the pkgver will change.
        # It isn't useful to include it in the diff output.
        old_pkginfo_data = strip_pkginfo_pkgver(old_pkginfo_data)
        new_pkginfo_data = strip_pkginfo_pkgver(new_pkginfo_data)

    with (
        tempfile.NamedTemporaryFile() as stripped_old_pkginfo_file,
        tempfile.NamedTemporaryFile() as stripped_new_pkginfo_file,
        output.open("w", encoding="utf-8") as output_file,
    ):
        stripped_old_pkginfo_file.write(old_pkginfo_data.encode("utf-8"))
        stripped_old_pkginfo_file.flush()
        stripped_new_pkginfo_file.write(new_pkginfo_data.encode("utf-8"))
        stripped_new_pkginfo_file.flush()

        diff_result = subprocess.run(
            [
                "diff",
                "-u",
                "-L",
                "old/.PKGINFO",
                "-L",
                "new/.PKGINFO",
                stripped_old_pkginfo_file.file.name,
                stripped_new_pkginfo_file.file.name,
            ],
            check=False,
            stdout=output_file,
        )

        match diff_result.returncode:
            case 0:
                return False
            case 1:
                return True
            case x:
                print(f"::error::diff returned an unexpected exit code: {x}")
                sys.exit(1)


def diff_data_files(pkgs_dir: Path, output: Path) -> bool:
    with output.open("w", encoding="utf-8") as output_file:
        diff_result = subprocess.run(
            [
                "git",
                "diff",
                "--no-index",
                Path(OLD_DIR_NAME) / DATA_DIR_NAME,
                Path(NEW_DIR_NAME) / DATA_DIR_NAME,
            ],
            check=False,
            cwd=pkgs_dir,
            stdout=output_file,
        )

    match diff_result.returncode:
        case 0:
            return False
        case 1:
            return True
        case x:
            print(f"::error::git diff returned an unexpected exit code: {x}")
            sys.exit(1)


def package_list_to_dict(items: list[str]) -> dict[str, str]:
    """
    Converts a list of strings in the format "key=value" into a dictionary.
    """
    return dict(item.split("=", 1) for item in items)


def main(
    old_pkg: Annotated[Path, typer.Argument(help="Path to the old APK package.")],
    new_pkg: Annotated[Path, typer.Argument(help="Path to the new APK package.")],
    show_summary: Annotated[
        bool, typer.Option(help="Show the diff report in the step summary")
    ] = False,
):
    runner_temp: Final[str | None] = os.environ.get("RUNNER_TEMP")
    if runner_temp is None:
        print("RUNNER_TEMP environment variable is not set.")
        sys.exit(1)

    github_output: Final[str | None] = os.environ.get("GITHUB_OUTPUT")
    if github_output is None:
        print("GITHUB_OUTPUT environment variable is not set.")
        sys.exit(1)

    github_step_summary: Final[str | None] = os.environ.get("GITHUB_STEP_SUMMARY")
    if github_step_summary is None:
        print("GITHUB_STEP_SUMMARY environment variable is not set.")
        sys.exit(1)

    out_dir = Path(tempfile.mkdtemp(dir=runner_temp))

    old_pkg_dir = out_dir / OLD_DIR_NAME
    new_pkg_dir = out_dir / NEW_DIR_NAME

    old_pkg_dir.mkdir()
    new_pkg_dir.mkdir()

    print("Extracting old package...")
    extract_apk(old_pkg, old_pkg_dir)

    print("Extracting new package...")
    extract_apk(new_pkg, new_pkg_dir)

    old_pkginfo_file = old_pkg_dir / PKGINFO_FILE_PATH
    new_pkginfo_file = new_pkg_dir / PKGINFO_FILE_PATH

    diff_pkginfo_file = out_dir / "PKGINFO.diff"

    print("Diffing .PKGINFO files...")
    pkginfo_changed = diff_pkginfo(
        old_pkginfo_file, new_pkginfo_file, diff_pkginfo_file
    )

    old_melange_config_file = old_pkg_dir / MELANGE_CONFIG_FILE_PATH
    new_melange_config_file = new_pkg_dir / MELANGE_CONFIG_FILE_PATH

    print("Loading .melange.yaml files...")
    old_melange_config = MelangeConfig.model_validate(
        yaml.safe_load(old_melange_config_file.read_text(encoding="utf-8"))
    )
    new_melange_config = MelangeConfig.model_validate(
        yaml.safe_load(new_melange_config_file.read_text(encoding="utf-8"))
    )

    print("Diffing build environment...")
    old_build_packages = package_list_to_dict(
        old_melange_config.environment.contents.packages
    )
    new_build_packages = package_list_to_dict(
        new_melange_config.environment.contents.packages
    )

    build_package_names = sorted(
        set(list(old_build_packages.keys()) + list(new_build_packages.keys()))
    )

    build_env_changed = False
    build_packages: dict[str, tuple[str | None, str | None]] = {}
    for package in build_package_names:
        old_version = old_build_packages.get(package)
        new_version = new_build_packages.get(package)
        build_packages[package] = (old_version, new_version)
        if old_version != new_version:
            build_env_changed = True

    print("Diffing data files...")
    data_diff = out_dir / "data.diff"
    data_changed = diff_data_files(out_dir, data_diff)

    print("Generating summary...")
    env = Environment(
        loader=FileSystemLoader(TEMPLATES_DIR),
        autoescape=select_autoescape(["md.j2"]),
        extensions=["jinja2.ext.do"],
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )

    summary_tmpl = env.get_template("diff-report.md.j2")

    diff_report = summary_tmpl.render(
        pkginfo_changed=pkginfo_changed,
        pkginfo_diff=diff_pkginfo_file.read_text(encoding="utf-8"),
        pkginfo_old=old_pkginfo_file.read_text(encoding="utf-8"),
        pkginfo_new=new_pkginfo_file.read_text(encoding="utf-8"),
        build_env_changed=build_env_changed,
        build_packages=build_packages,
        data_changed=data_changed,
        data_diff=data_diff.read_text(encoding="utf-8"),
    )

    with tempfile.NamedTemporaryFile(
        mode="wt",
        encoding="utf-8",
        dir=runner_temp,
        delete=False,
        delete_on_close=False,
    ) as diff_report_file:
        diff_report_file.write(diff_report)

    if show_summary:
        Path(github_step_summary).write_text(diff_report, encoding="utf-8")

    with open(github_output, "a", encoding="utf-8") as f:
        f.write(f"package_changed={'true' if pkginfo_changed else 'false'}\n")
        f.write(f"report_md_file={diff_report_file.name}")


if __name__ == "__main__":
    typer.run(main)
