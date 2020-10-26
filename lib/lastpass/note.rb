module LastPass
    class Note
        attr_reader :id,
                    :name,
                    :notes,
                    :group

        def initialize id, name, notes, group
            @id = id
            @name = name
            @notes = notes
            @group = group
        end
    end
end
