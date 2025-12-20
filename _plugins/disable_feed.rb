#!/usr/bin/env ruby
#
# Plugin to disable feed.xml generation

Jekyll::Hooks.register :site, :post_write do |site|
  feed_path = File.join(site.dest, "feed.xml")
  if File.exist?(feed_path)
    File.delete(feed_path)
    Jekyll.logger.info "Removed feed.xml"
  end
end

