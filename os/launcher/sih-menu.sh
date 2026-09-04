#!/bin/sh
# SIH Recovery OS - boot menu
# Plain numbered menu, no GUI toolkit required. Runs as the console's
# entry point (see /etc/inittab tty1 line) and re-launches itself after
# each tool exits, so the console never drops to a bare login prompt.
#
# Binaries are expected at /opt/sih/bin/ once the custom ISO profile is
# in place; for now this can be pointed at your build/ dir for testing.

BIN_DIR="${SIH_BIN_DIR:-/opt/sih/bin}"

show_menu() {
    clear
    echo "============================================="
    echo "   SIH Recovery OS"
    echo "============================================="
    echo ""
    echo "   1) Sanitize a drive"
    echo "   2) Recover files"
    echo "   3) Device information"
    echo "   4) Terminal"
    echo ""
    echo "============================================="
    printf "Select an option [1-4]: "
}

while true; do
    show_menu
    read -r choice

    case "$choice" in
        1)
            "$BIN_DIR/sanitizer"
            ;;
        2)
            "$BIN_DIR/recovery-test"
            ;;
        3)
            "$BIN_DIR/device-test"
            ;;
        4)
            echo "Type 'exit' to return to the menu."
            /bin/sh
            ;;
        *)
            echo "Invalid choice."
            sleep 1
            ;;
    esac
done