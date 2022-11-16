# Redis Community Edition Baseline

Test suite for best practice hardening of Redis Community Edition.

## Standalone Usage

This compliance profile requires [InSpec](https://github.com/chef/inspec) for execution:

```shell
$ git clone https://github.com/lonkey/redis-baseline
$ inspec exec redis-baseline
```

You can also execute the profile directly from GitHub:

```shell
$ inspec exec https://github.com/lonkey/redis-baseline
```

## License and Author

- Author: Lukas Zorn <github@lukaszorn.de>

- Copyright 2022, Lukas Zorn

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
