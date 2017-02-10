require "spec_helper"

describe OmniAuth::Strategies::Linnworks do
  def app
    lambda do |_env|
      [200, {}, ["Hello."]]
    end
  end
  let(:strategy) { Class.new(OmniAuth::Strategies::Linnworks) }

  describe "#client_options" do
    subject { strategy.new(app).options.client_options }

    it 'should have correct site' do
      expect(subject.site).to eq("http://apps.linnworks.net")
    end

    it 'should have correct authorize url' do
      expect(subject.authorize_url).to eq('/Authorization/Authorize')
    end

    it 'should have tracking' do
      expect(subject.tracking).to eq(nil)
    end
  end
end