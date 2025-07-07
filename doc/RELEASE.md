- Clean up CHANGELOG.md
- `cargo release minor`
- `cargo release alpha --no-tag`
- Add CHANGELOG stub
- push
- download artifacts

```
mv ../crate.zip ../deb.zip ../el8.zip ../el9.zip ../el10.zip .
for i in *.zip ; do unzip $i ; done
find . -mindepth 2 -type f -exec mv {} . ';'
```
