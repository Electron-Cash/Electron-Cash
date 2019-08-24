#!/usr/bin/ruby
require 'xcodeproj'
require 'open3'

project_path = "iOS/Electron-Cash.xcodeproj";

# Create project object
project = Xcodeproj::Project.open(project_path);

stdout,stderr,status = Open3.capture3("/usr/bin/xcode-select -print-path")

if status
  lib = stdout.strip + '/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk/usr/lib/libxml2.tbd'
else
  puts "Xcode not found!"
  exit(1)
end

#puts lib

project.targets.each do |target|
  build_phase = target.frameworks_build_phase
  framework_group = project.frameworks_group
  file_ref = framework_group.new_reference(lib)
  build_file = build_phase.add_file_reference(file_ref)
end

# Save the project
project.save();


