mkdir -p dist/dmg
# Empty the dmg folder.
rm -r dist/dmg/*
# Copy the app bundle to the dmg folder.
cp -r "dist/Soteris Encrypt.app" dist/dmg
# If the DMG already exists, delete it.
test -f "dist/Soteris Encrypt.dmg" && rm "dist/Soteris Encrypt.dmg"
create-dmg \
  --volname "Soteris Installer" \
  --volicon "favicon.icns" \
  --window-pos 200 120 \
  --window-size 600 300 \
  --icon-size 100 \
  --icon "Soteris Encrypt.app" 175 120 \
  --hide-extension "Soteris Encrypt.app" \
  --app-drop-link 425 120 \
  "dist/Soteris Installer.dmg" \
  "dist/dmg/"
