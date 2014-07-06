Before do
  @blocks = {}
  @addresses = {}
  @nodes = {}
  @tx = {}
  @pubkeys = {}
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

Then(/^all nodes should (?:be at|reach) block "(.*?)"$/) do |block|
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

When(/^node "(.*?)" retrieves the public key of the "(.*?)" address$/) do |arg1, arg2|
  info = @nodes[arg1].rpc("validateaddress", @addresses[arg2])
  @pubkeys[arg2] = info["pubkey"]
end

When(/^all nodes are after the protocol V05 switch time$/) do
  source_path = File.expand_path('../../../../kernel.cpp', __FILE__)
  if File.read(source_path) =~ /nProtocolV05TestSwitchTime *= *(\d+);/
    switch_time = Time.at($1.to_i + 1)
  else
    raise "Protocol V05 switch time not found in #{source_path}"
  end
  @nodes.values.each do |node|
    time = Time.parse(node.info["time"])
    if time < switch_time
      node.rpc("timetravel", (switch_time - time).to_i)
    end
  end
  @time_shift = switch_time - Time.now
end

When(/^all nodes reach (\d+) transactions? in memory pool$/) do |arg1|
  wait_for do
    expect(@nodes.values.map { |node| node.rpc("getmininginfo")["pooledtx"] }).to eq(Array.new(@nodes.size, arg1.to_i))
  end
end

When(/^node "(.*?)" finds blocks until just received coins are able to mint$/) do |arg1|
  node = @nodes[arg1]
  min_age = 60 * 60 * 24
  blocks = 5
  time_between_blocks = min_age / blocks
  blocks.times do
    time_travel(time_between_blocks)
    node.rpc("generatestake")
  end
  max_age = 60 * 60 * 24 * 90
  time_travel(max_age - min_age)
  node.rpc("generatestake")
  step 'all nodes reach the same height'
end

When(/^node "(.*?)" finds enough blocks for a Proof of Stake block to mint again$/) do |arg1|
  step "node \"#{arg1}\" finds blocks until just received coins are able to mint"
end

Then(/^node "(.*?)" should be able to find a block "(.*?)"$/) do |arg1, arg2|
  step "node \"#{arg1}\" finds a block \"#{arg2}\""
end

Then(/^node "(.*?)" should not be able to find a block "(.*?)"$/) do |arg1, arg2|
  node = @nodes[arg1]
  expect(node.rpc("generatestake", DEFAULT_TIMEOUT / 2)).to eq("0000000000000000000000000000000000000000000000000000000000000000")
end

Then(/^node "(.*?)" should have a stake of "([^"]*?)"$/) do |arg1, arg2|
  wait_for do
    expect(@nodes[arg1].info["stake"]).to eq(parse_number(arg2))
  end
end

Then(/^node "(.*?)" should have a stake of "(.*?)" \+ the reward on block "(.*?)"$/) do |arg1, arg2, arg3|
  node = @nodes[arg1]
  expected_stake = parse_number(arg2)
  block = @blocks[arg3]

  block_info = node.rpc("getblock", block)
  reward = block_info["mint"]
  expected_stake += reward
  expect(node.info["stake"]).to eq(expected_stake)
end

When(/^node "(.*?)" finds enough blocks for a Proof of Stake block to mature$/) do |arg1|
  node = @nodes[arg1]
  (5 + 1).times do
    time_travel 30 * 60
    node.generate_stake
  end
end

When(/^node "(.*?)" dumps the private key of "(.*?)"$/) do |arg1, arg2|
  node = @nodes[arg1]
  address_name = arg2

  @private_keys ||= {}
  @private_keys[address_name] = node.rpc("dumpprivkey", @addresses[address_name])
end

When(/^node "(.*?)" imports the private key of "(.*?)"$/) do |arg1, arg2|
  node = @nodes[arg1]
  address_name = arg2

  node.rpc("importprivkey", @private_keys[address_name])
end

Then(/^node "(.*?)" should have a balance of "(.*?)" \+ the reward on block "(.*?)"$/) do |arg1, arg2, arg3|
  node = @nodes[arg1]
  expected_balance = parse_number(arg2)
  block = @blocks[arg3]

  block_info = node.rpc("getblock", block)
  reward = block_info["mint"]
  expected_balance += reward
  expect(node.info["balance"]).to eq(expected_balance)
end
