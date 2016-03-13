cat * | jq .[] | jq ."Attribute" | jq '.[] | select(.type | contains("md5"))' | jq .value > md5_dirty
cat md5_dirty | grep "|" | cut -d\| -f2 | cut -d\" -f 1 >> md5_clean
cat md5_dirty | grep -v "|" | cut -d\" -f 2 >> md5_clean
cat md5_clean | sort -u > md5_uniq


cat * | jq .[] | jq ."Attribute" | jq '.[] | select(.type | contains("sha1"))' | jq .value > sha1_dirty
cat sha1_dirty | grep "|" | cut -d\| -f2 | cut -d\" -f 1 >> sha1_clean
cat sha1_dirty | grep -v "|" | cut -d\" -f 2 >> sha1_clean
cat sha1_clean | sort -u > sha1_uniq

cat * | jq .[] | jq ."Attribute" | jq '.[] | select(.type | contains("sha256"))' | jq .value > sha256_dirty
cat sha256_dirty | grep "|" | cut -d\| -f2 | cut -d\" -f 1 >> sha256_clean
cat sha256_dirty | grep -v "|" | cut -d\" -f 2 >> sha256_clean
cat sha256_clean | sort -u > sha256_uniq

