#!/usr/bin/ruby
require 'xcodeproj'

# This should be the Xcode ID for the team
dev_team = "MZ11Z1Z11Z";

project_path = "iOS/Electron-Cash.xcodeproj";

# Create project object
project = Xcodeproj::Project.open(project_path);

lib = '/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/usr/lib/libxml2.tbd'

project.targets.each do |target|
  build_phase = target.frameworks_build_phase
  framework_group = project.frameworks_group
  file_ref = framework_group.new_reference(lib)
  build_file = build_phase.add_file_reference(file_ref)
  target.build_configurations.each do |config|
    config.build_settings["DEVELOPMENT_TEAM"] =  dev_team
  end
end

# Save the project
project.save();


