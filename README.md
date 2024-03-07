# Casio Notebook Loader

## Install

1. Copy [HCD62121 processor module](https://github.com/qufb/HCD62121) to `$GHIDRA_INSTALL_DIR/Processors/`.
1. Build and copy loader:
    ```sh
    gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR buildExtension
    mv dist/ghidra_*.zip "$GHIDRA_INSTALL_DIR/Extensions/Ghidra/"
    ```
