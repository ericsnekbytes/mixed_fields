# MixedFields Binary Format

MixedFields is a lightweight, variable field length binary format. It's currently in pre-alpha.

Writing binary data to a file:

```
>>> import mixed_fields
>>> mf = mixed_fields.MixedFields(r'test.mixd')
>>> mf.write_item(b'Spam')
>>> mf.write_item(b'And eggs!')
>>> mf.write_item(b'We require...a shrubbery!')
>>> mf.write_item(b'\x01\x02\x03\x04')
>>> import pickle
>>> mf.write_item(pickle.dumps({'keyA': 'valueA'}))
>>> mf.close()
```

Lazy read items from the same MixedFields file:

```
>>> import mixed_fields
>>> mf = mixed_fields.MixedFields(r'test.mixd')
>>> mf.read_item()
b'Spam'
>>> mf.read_item()
b'And eggs!'
>>> mf.read_item()
b'We require...a shrubbery!'
>>> mf.read_item()
b'\x01\x02\x03\x04'
>>> val = pickle.loads(mf.read_item()); val
{'keyA': 'valueA'}
>>> mf.read_item()  # Note, empty bytes means EOF has been reached
b''
```

The file format consists entirely of tagged fields, where each field is
`<tag> + <payload> + <endbyte>`. Tags are `<start_byte> + <4 letter tag name>`,
for example the header tag is `b'\x1cMixd'`.

Variable size fields have a length subfield just before the payload, which
itself is variable size (the leading bit of each byte is 1 when there's a
continuation byte, and 0 when the last byte of the size field has been reached,
so 7 bit lengths only need 1 size byte starting with 0).

Every file has a `header` field, `metadata` field (variable length), optionally
some `data` fields, and an `end-of-file` field.

Currently, only data fields can be added by users. User metadata fields and fixed
length fields are planned for the future, as well as custom user fields.
