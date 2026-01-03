Build
```sh
flatpak-builder --force-clean --user --install-deps-from=flathub --repo=repo --install builddir io.github.ozordi.sanrecomp.json
```

Bundle
```sh
flatpak build-bundle repo io.github.ozordi.sanrecomp.flatpak io.github.ozordi.sanrecomp --runtime-repo=https://flathub.org/repo/flathub.flatpakrepo
```
