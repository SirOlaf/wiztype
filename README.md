# wiztype
A type dumper for wizard101

## install
`pip install wiztype`

## usage
an instance of wizard101 must be open for all commands

```shell
# generate a normal dump in the current directory named after the current revision
$ wiztype
# generate a dump with indent level 4 (for human reading)
$ wiztype --indent 4
# generate a version 2 dump (no aliases or core object factory types)
$ wiztype --version 2
# generate a version 1 dump (wizwalker)
$ wiztype --version 1 --indent 4
```

## support
discord: <https://discord.gg/wcftyYm6qe>

## json spec

```json5
{
  "version": 3,
  "classes": {
    "class hash (as string)": {
      "bases": ["class base classes"],
      "name": "class name",
      "singleton": true,
      "properties": {
        "property name": {
          "type": "property type",
          "id": 123,
          "offset": 123,
          "flags": 123,
          "container": "container name",
          "dynamic": true,
          "pointer": true,
          "hash": 123,
          "enum_options": {
            "option name": 123,
            // __DEFAULT is a string
            "__DEFAULT": "option name",
            // __BASECLASS is a string
            "__BASECLASS": "option name",
          }
        }
      }
    }
  },
  // types registered under an additional hash, the serializer resolves these
  // to the target type; only the hash of the alias name exists in the client
  "aliases": {
    "alias hash (as string)": 123 // target class hash
  },
  // types CoreObjectFactory can create
  "core_object_factory_types": {
    "core type (as string)": {
      "namespace": 0,
      // hash of the CoreObject type name, a djb2 variant (not a class hash)
      "type_hash": 123
    }
  }
}
```
