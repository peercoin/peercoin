require 'timeout'
def wait_for(timeout = 5)
  last_exception = nil
  begin
    Timeout.timeout(timeout) do
      loop do
        begin
          break if yield
        rescue RSpec::Expectations::ExpectationNotMetError, RuntimeError => e
          last_exception = e
        end
        sleep 0.1
      end
    end
  rescue Timeout::Error
    if last_exception
      raise last_exception
    else
      raise
    end
  end
end

def parse_number(n)
  n.gsub(',', '').to_f
end

def time_travel(seconds)
  @nodes.values.each do |node|
    node.rpc("timetravel", seconds)
  end
  @time_shift += seconds
end
