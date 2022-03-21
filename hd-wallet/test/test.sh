#!/usr/bin/env bash

BASE=$(dirname $0)
TESTS=$(cd "$BASE"; find * -maxdepth 0 -type d | grep -v node_modules)

if [[ "$*" != "" ]]; then
  TESTS="$*"
fi

if [[ "$SDKMS_API_KEY" == "" ]]; then
  echo "Please set SDKMS_API_KEY before running these tests."
  exit 1
fi

if [[ "$SDKMS_PLUGIN_UUID" == "" ]]; then
  echo "Please set SDKMS_PLUGIN_UUID before running these tests."
  exit 1
fi

export SDKMS_API_ENDPOINT=${SDKMS_API_ENDPOINT:-"https://sdkms.fortanix.com"}
BASE=$(dirname $0)

echo "Logging in..."
sdkms-cli app-login --api-key $SDKMS_API_KEY

get_diff() {
  TMPDIR=$(mktemp -d)
  pushd $TMPDIR >/dev/null 2>&1
  echo "$1" > expected
  echo "$2" > actual
  colordiff -u expected actual | diff-highlight
  rm actual expected
  popd >/dev/null 2>&1
  rmdir $TMPDIR
}

compare() {
  actual="$1"
  expected="$2"
  t="$3"
  if [[ "$actual" != "$expected" ]]; then
    echo -n "fail $t  "
    echo
    echo "Expected:"
    echo "$expected"
    echo
    echo "Actual:"
    echo "$actual"
    echo
    echo "Diff:"
    echo "$(get_diff "$expected" "$actual")"
  else
    echo -n "pass $t  "
  fi
}

for test in $TESTS; do
  echo -n "Testing $test ... "

  # Load xprv for this test into SDKMS
  xprv=$(cat $BASE/${test}/keys.json | jq -r .xprv)
  xpub=$(cat $BASE/${test}/keys.json | jq -r .xpub)
  keyid=$(echo $xprv | sdkms-cli import-secret --in /dev/stdin --name $xpub)

  EXPECTED=$(cat $BASE/${test}/output.json | jq -M -S .)
  EXPECTED_RAW=$(cat $BASE/${test}/raw.json | jq -M -S .)
  ACTUAL=$(cat $BASE/${test}/input.json | jq ".masterKeyId = \"${keyid}\"" | sdkms-cli --prefer-app-auth invoke-plugin --id $SDKMS_PLUGIN_UUID --in /dev/stdin | jq -M -S .)
  NORMALIZED=$(echo "$ACTUAL" | jq ". += $(cat $BASE/${test}/keys.json)" | jq ". += $(cat $BASE/${test}/input.json)" | $BASE/normalize.js | jq -M -S .)

  compare "$NORMALIZED" "$EXPECTED" normalized
  compare "$ACTUAL" "$EXPECTED_RAW" raw
  echo

  # Remove xprv from SDKMS
  sdkms-cli delete-key --kid $keyid
done
