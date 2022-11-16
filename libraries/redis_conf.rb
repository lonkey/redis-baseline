# Copyright: 2022, Lukas Zorn
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Lukas Zorn

require "inspec/utils/file_reader"
require "inspec/utils/simpleconfig"

module Inspec::Resources
  class RedisConf < Inspec.resource(1)
    name "redis_conf"
    supports platform: "unix"
    desc "Use the redis_conf InSpec audit resource to test the settings defined in the redis.conf file. This file is typically located at /etc/redis/redis.conf."
    example <<~EXAMPLE
      describe redis_conf do
        its('port') { should eq '0' }
        its('tls_port') { should eq('6379') }
      end
    EXAMPLE

    include FileReader

    def initialize(path = nil)
      @conf_path = path || "/etc/redis/redis.conf"
      @content = read_file_content(@conf_path)
    end

    def method_missing(name)
      param = read_params[name.to_s]
      return param[0] if param.is_a?(Array) && (param.length == 1)

      param
    end

    def resource_id
      @conf_path || "redis_conf"
    end

    def to_s
      "redis.conf"
    end

    private

    def read_params
      return @params if defined?(@params)

      conf = SimpleConfig.new(
        @content,
        assignment_regex: /^\s*(\S+)\s+(.*)\s*$/,
        multiple_values: true
      )
      @params = conf.params
    end
  end
end