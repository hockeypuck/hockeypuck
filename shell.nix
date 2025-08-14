with import <nixos-unstable> {};
runCommand "dummy" { buildInputs = [ go_1_21 gnumake gcc ]; } ""
