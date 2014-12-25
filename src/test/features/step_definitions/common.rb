Before do
  @blocks = {}
  @addresses = {}
  @nodes = {}
  @tx = {}
  protocol_v04_switch = Time.at(1395700000)
  net_start = protocol_v04_switch + 24 * 3600
  container_start = net_start + 90 * 24 * 3600
  @time_shift = container_start - Time.now
end

Given(/^a network with nodes? (.+) able to mint$/) do |node_names|
  node_names = node_names.scan(/"(.*?)"/).map(&:first)
  available_nodes = %w( a b c d e )
  raise "More than #{available_nodes.size} nodes not supported" if node_names.size > available_nodes.size
  @nodes = {}

  node_names.each_with_index do |name, i|
    options = {
      image: "peercoinnet/#{available_nodes[i]}",
      links: @nodes.values.map(&:name),
      args: {
        timetravel: @time_shift,
      },
      display_name: name,
    }
    node = CoinContainer.new(options)
    @nodes[name] = node
    node.wait_for_boot
  end

  wait_for(10) do
    @nodes.values.all? do |node|
      count = node.connection_count
      count == @nodes.size - 1
    end
  end
  wait_for do
    @nodes.values.map do |node|
      count = node.block_count
      count
    end.uniq.size == 1
  end
end

Given(/^a node "(.*?)" connected only to node "(.*?)"$/) do |arg1, arg2|
  other_node = @nodes[arg2]
  name = arg1
  options = {
    image: "peercoinnet/a",
    links: [other_node.name],
    link_with_connect: true,
    args: {
      timetravel: @time_shift,
    },
    remove_wallet_before_startup: true,
    display_name: name,
  }
  node = CoinContainer.new(options)
  @nodes[name] = node
  node.wait_for_boot
  wait_for do
    expect(node.info["connections"]).to eq(1)
  end
end

Given(/^a node "(.*?)" with an empty wallet$/) do |arg1|
  name = arg1
  options = {
    image: "peercoinnet/a",
    links: @nodes.values.map(&:name),
    args: {
      timetravel: @time_shift,
    },
    remove_wallet_before_startup: true,
    display_name: name,
  }
  node = CoinContainer.new(options)
  @nodes[name] = node
  node.wait_for_boot
end

After do
  if @nodes
    require 'thread'
    @nodes.values.reverse.map do |node|
      Thread.new do
        node.shutdown
        #node.wait_for_shutdown
        #begin
        #  node.container.delete(force: true)
        #rescue
        #end
      end
    end.each(&:join)
  end
end

When(/^node "(.*?)" finds a block "([^"]*?)"$/) do |node, block|
  @blocks[block] = @nodes[node].generate_stake
end

When(/^node "(.*?)" finds a block "([^"]*?)" not received by node "([^"]*?)"$/) do |node, block, other|
  time_travel(5)
  @nodes[other].rpc("ignorenextblock")
  @blocks[block] = @nodes[node].generate_stake
end

When(/^node "(.*?)" finds a block$/) do |node|
  @nodes[node].generate_stake
end

Then(/^all nodes should be at block "(.*?)"$/) do |block|
  begin
    wait_for do
      main = @nodes.values.map(&:top_hash)
      main.all? { |hash| hash == @blocks[block] }
    end
  rescue
    require 'pp'
    pp @blocks
    raise "Not at block #{block}: #{@nodes.values.map(&:top_hash).map { |hash| @blocks.key(hash) || hash }.inspect}"
  end
end

Then(/^nodes? (.+) (?:should be at|should reach|reach|reaches|is at|are at) block "(.*?)"$/) do |node_names, block|
  nodes = node_names.scan(/"(.*?)"/).map { |name, | @nodes[name] }
  begin
    wait_for do
      main = nodes.map(&:top_hash)
      main.all? { |hash| hash == @blocks[block] }
    end
  rescue
    require 'pp'
    pp @blocks
    raise "Not at block #{block}: #{nodes.map(&:top_hash).map { |hash| @blocks.key(hash) || hash }.inspect}"
  end
end

Given(/^all nodes (?:should )?reach the same height$/) do
  wait_for do
    expect(@nodes.values.map(&:block_count).uniq.size).to eq(1)
  end
end

When(/^node "(.*?)" sends "(.*?)" to "([^"]*?)" in transaction "(.*?)"$/) do |arg1, arg2, arg3, arg4|
  @tx[arg4] = @nodes[arg1].rpc "sendtoaddress", @addresses[arg3], parse_number(arg2)
end

When(/^node "(.*?)" sends "(.*?)" to "([^"]*?)"$/) do |arg1, arg2, arg3|
  @nodes[arg1].rpc "sendtoaddress", @addresses[arg3], parse_number(arg2)
end

When(/^node "(.*?)" finds a block received by all other nodes$/) do |arg1|
  node = @nodes[arg1]
  block = node.generate_stake
  wait_for do
    main = @nodes.values.map(&:top_hash)
    main.all? { |hash| hash == block }
  end
end

Given(/^node "(.*?)" generates a new address "(.*?)"$/) do |arg1, arg2|
  @addresses[arg2] = @nodes[arg1].rpc("getnewaddress")
end

When(/^node "(.*?)" sends "(.*?)" to "(.*?)" through transaction "(.*?)"$/) do |arg1, arg2, arg3, arg4|
  @tx[arg4] = @nodes[arg1].rpc "sendtoaddress", @addresses[arg3], parse_number(arg2)
end

Then(/^transaction "(.*?)" on node "(.*?)" should have (\d+) confirmations?$/) do |arg1, arg2, arg3|
  wait_for do
    expect(@nodes[arg2].rpc("gettransaction", @tx[arg1])["confirmations"]).to eq(arg3.to_i)
  end
end

Then(/^all nodes should (?:have|reach) (\d+) transactions? in memory pool$/) do |arg1|
  wait_for do
    expect(@nodes.values.map { |node| node.rpc("getmininginfo")["pooledtx"] }).to eq(@nodes.map { arg1.to_i })
  end
end

Given(/^node "(.*?)" (?:should |)(?:reaches|have) a balance of "([^"]*?)"$/) do |arg1, arg2|
  wait_for do
    expect(@nodes[arg1].rpc("getbalance")).to eq(parse_number(arg2))
  end
end

Then(/^node "(.*?)" should have (\d+) connection$/) do |arg1, arg2|
  expect(@nodes[arg1].info["connections"]).to eq(arg2.to_i)
end
