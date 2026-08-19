BEGIN {
  FS = "="
}

NR == FNR {
  old[$1] = $2
  next
}

{
  new[$1] = $2
}

END {
  PROCINFO["sorted_in"] = "@ind_str_asc"

  print "## Added"
  print "| Package | Version |"
  print "|---------|---------|"

  for (pkg in new) if (!(pkg in old)) print "| " pkg " | " new[pkg] " |"

  print ""

  print "## Removed"
  print "| Package | Version |"
  print "|---------|---------|"

  for (pkg in old) if (!(pkg in new)) print "| " pkg " | " old[pkg] " |"

  print ""

  print "## Changed"
  print "| Package | Old Version | New Version |"
  print "|---------|-------------|-------------|"

  for (pkg in new) if ((pkg in old) && (new[pkg] != old[pkg])) print "| " pkg " | " old[pkg] " | " new[pkg] " |"

  print ""

  print "<details>"
  print "<summary>Show unchanged packages</summary>"
  print ""
  print "## Same"
  print "| Package | Version |"
  print "|---------|---------|"

  for (pkg in new) if ((pkg in old) && (new[pkg] == old[pkg])) print "| " pkg " | " new[pkg] " |"

  print "</details>"
  print ""
}
