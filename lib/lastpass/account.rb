# Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
# Licensed under the terms of the MIT license. See LICENCE for details.

module LastPass
    class Account
        attr_reader :id,
                    :name,
                    :username,
                    :password,
                    :url,
                    :group

        def initialize id, name, username, password, url, group
            @id = id
            @name = name
            @username = username
            @password = password
            @url = url
            @group = group
        end
    end
end
