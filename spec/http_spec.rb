require "spec_helper"

describe LastPass::HTTP do
  let(:http) { LastPass::HTTP }

  it 'can set the proxy options' do
    http.http_proxy('proxy.fazbearentertainment.com', 1987, 'ffazbear', 'itsme')
    options = http.instance_variable_get(:@default_options)
    expect(options[:http_proxyaddr]).to eq('proxy.fazbearentertainment.com')
    expect(options[:http_proxyport]).to eq(1987)
    expect(options[:http_proxyuser]).to eq('ffazbear')
    expect(options[:http_proxypass]).to eq('itsme')
  end
end
