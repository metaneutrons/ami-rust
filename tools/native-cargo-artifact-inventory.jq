# Validate all GitHub artifact pages before using their active byte counts.
def bounded_integer:
  type == "number" and . == floor and . >= 0 and . <= 9007199254740991;
if type != "array" or length == 0 then error("artifact pages are missing")
elif all(.[];
  type == "object" and (.artifacts | type == "array") and
  all(.artifacts[];
    type == "object" and (.id | bounded_integer and . > 0) and
    (.name | type == "string" and length > 0) and
    (.expired | type == "boolean") and (.size_in_bytes | bounded_integer)))
then [.[].artifacts[]] as $rows |
  if ($rows | map(.id) | unique | length) != ($rows | length)
  then error("duplicate artifact identity")
  else [$rows[] | select(.expired == false)] |
    if (map(.size_in_bytes) | add // 0) > 9007199254740991
    then error("artifact byte total is not exactly representable")
    else . end
  end
else error("artifact page or record schema invalid") end
