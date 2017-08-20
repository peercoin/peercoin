When(/^node "(.*?)" sends a duplicate "([^"]*?)" of block "([^"]*?)"$/) do |node, duplicate, original|
  @blocks[duplicate] = @nodes[node].rpc("duplicateblock", @blocks[original])
end

When(/^node "(.*?)" sends a duplicate "([^"]*?)" of block "([^"]*?)" not received by node "(.*?)"$/) do |node, duplicate, original, other|
  @nodes[other].rpc("ignorenextblock")
  @blocks[duplicate] = @nodes[node].rpc("duplicateblock", @blocks[original])
end

When(/^node "(.*?)" finds a block "(.*?)" on top of block "(.*?)"$/) do |node, block, parent|
  @blocks[block] = @nodes[node].generate_stake(@blocks[parent])
  block_info = @nodes[node].rpc("getblock", @blocks[block])
  expect(block_info["previousblockhash"]).to eq(@blocks[parent])
end
