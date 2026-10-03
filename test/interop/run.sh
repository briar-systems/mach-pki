#!/usr/bin/env bash
# check cms interop with openssl in both directions, with fresh keys
#
#   test/interop/run.sh
#
# openssl verifies the signed data mach-pki builds for every algorithm, attached
# and detached, and mach-pki verifies what openssl signs. it runs locally, not
# in ci
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=$here/out/run
"$here/generate.sh" "$work"
mach dep pull "$here" >/dev/null
mach build "$here"
bin=$here/out/linux-x86_64/debug/bin/interop

status=0
for pair in ed25519:ed25519 p256:p256 pss256:rsa pss384:rsa; do
    algorithm=${pair%%:*}
    key=${pair##*:}
    for form in attached detached; do
        out=$work/mach-$algorithm-$form.der
        "$bin" sign "$work/$key.key" "$work/$key-chain.pem" "$work/content.txt" "$form" \
            "$algorithm" "$out"
        content=()
        if [ "$form" = detached ]; then content=(-content "$work/content.txt"); fi
        if openssl cms -verify -binary -inform DER -in "$out" -CAfile "$work/root.pem" \
            -purpose smimesign "${content[@]}" -out /dev/null 2>"$work/openssl.err"; then
            echo "openssl verifies mach-$algorithm-$form"
        else
            echo "openssl refuses mach-$algorithm-$form"
            cat "$work/openssl.err"
            status=1
        fi
    done
done

for signed in "$work"/openssl-*.der; do
    content=-
    case "$signed" in *-detached.der) content=$work/content.txt ;; esac
    if "$bin" verify "$signed" "$work/root.pem" "$content"; then
        echo "mach-pki verifies $(basename "$signed" .der)"
    else
        status=1
    fi
done
exit $status
