When(/^node "(.*?)" generates a new cold minting address "(.*?)" with the minting address "(.*?)" and the spending address "(.*?)"$/) do |arg1, arg2, arg3, arg4|
  node = @nodes[arg1]
  cold_minting_address_name = arg2
  minting_address = @addresses[arg3]
  spending_address = @addresses[arg4]

  @addresses[cold_minting_address_name] = node.rpc("addcoldmintingaddress", minting_address, spending_address)
end

Then(/^node "(.*?)" should have a minting only balance of "([^"]*?)"$/) do |arg1, arg2|
  expect(@nodes[arg1].info["mintingonly"]).to eq(parse_number(arg2))
end

When(/^node "(.*?)" should have a minting only balance of "(.*?)" \+ the reward on block "(.*?)"$/) do |arg1, arg2, arg3|
  node = @nodes[arg1]
  expected_mintingonly = parse_number(arg2)
  block = @blocks[arg3]

  block_info = node.rpc("getblock", block)
  reward = block_info["mint"]
  expected_mintingonly += reward
  expect(node.info["mintingonly"]).to eq(expected_mintingonly)
end
