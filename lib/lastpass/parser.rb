module LastPass
    class Parser
        class << self
            def parse blob
                parser = Parser.new blob
                parser.send :parse # to avoid exposing the private 'parse' method

                parser
            end
        end

        private

        def initialize blob
            @blob = blob
        end

        def parse
        end
    end
end
