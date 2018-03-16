#!/bin/bash

/usr/bin/env python3 --version | grep -q " 3.5"
if [ "$?" != "0" ]; then
	if /usr/bin/env python3 --version; then
		echo "WARNING:: Creating the Briefcase-based Xcode project for iOS requires Python 3.5."
		echo "We will proceed anyway -- but if you get errors, try switching to Python 3.5."
	else
		echo "ERROR: Python3+ is required"
		exit 1
	fi
fi

/usr/bin/env python3 -m pip show setuptools > /dev/null
if [ "$?" != "0" ]; then
	echo "ERROR: Please install setupdools like so: sudo python3 -m pip install briefcase"
	exit 2
fi

/usr/bin/env python3 -m pip show briefcase > /dev/null
if [ "$?" != "0" ]; then
	echo "ERROR: Please install briefcase like so: sudo python3 -m pip install briefcase"
	exit 3
fi

/usr/bin/env python3 -m pip show cookiecutter > /dev/null
if [ "$?" != "0" ]; then
	echo "ERROR: Please install cookiecutter like so: sudo python3 -m pip install cookiecutter"
	exit 4
fi

/usr/bin/env python3 -m pip show pbxproj > /dev/null
if [ "$?" != "0" ]; then
	echo "ERROR: Please install pbxproj like so: sudo python3 -m pip install pbxproj"
	exit 5
fi

if [ -d iOS ]; then
	echo "Warning: 'iOS' directory exists. All modifications will be lost if you continue."
	echo "Continue? [y/N]?"
	read reply
	if [ "$reply" != "y" ]; then
		echo "Fair enough. Exiting..."
		exit 0
	fi
	echo "Cleaning up old iOS dir..."
	rm -fr iOS
fi

if [ -d ElectronCash/electroncash ]; then
	echo "Deleting old ElectronCash/electroncash..."
	rm -fr ElectronCash/electroncash
fi

echo "Pulling 'electroncash' libs into project from ../lib ..."
if [ ! -d ../lib/locale ]; then
	(cd .. && contrib/make_locale && cd ios)
	if [ "$?" != 0 ]; then
		echo ERROR: Could not build locales
		exit 1
	fi
fi
cp -fpR ../lib ElectronCash/electroncash
find ElectronCash -name \*.pyc -exec rm -f {} \; 

echo ""
echo "Building Briefcase-Based iOS Project..."
echo ""

python3.5 setup.py ios 
if [ "$?" != 0 ]; then
	echo "An error occurred running setup.py"
	exit 4
fi

# No longer needed: they fixed the bug.  But leaving it here in case bug comes back!
#cd iOS && ln -s . Support ; cd .. # Fixup for broken Briefcase template.. :/

infoplist="iOS/ElectronCash/ElectronCash-Info.plist"
if [ -f "${infoplist}" ]; then
	echo ""
	echo "Adding custom keys to ${infoplist} ..."
	echo ""
	plutil -insert "NSAppTransportSecurity" -xml '<dict><key>NSAllowsArbitraryLoads</key><true/></dict>' -- ${infoplist} 
	if [ "$?" != "0" ]; then
		echo "Encountered error adding custom key NSAppTransportSecurity to plist!"
		exit 1
	fi
	#plutil -insert "UIBackgroundModes" -xml '<array><string>fetch</string></array>' -- ${infoplist}
	#if [ "$?" != "0" ]; then
	#	echo "Encountered error adding custom key UIBackgroundModes to plist!"
	#	exit 1
	#fi
	longver=`git describe --tags`
	if [ -n "$longver" ]; then
		shortver=`echo "$longver" | cut -f 1 -d -`
		plutil -replace "CFBundleVersion" -string "$longver" -- ${infoplist} && plutil -replace "CFBundleShortVersionString" -string "$shortver" -- ${infoplist}
		if [ "$?" != "0" ]; then
			echo "Encountered error adding custom keys to plist!"
			exit 1
		fi
	fi
	plutil -insert "NSCameraUsageDescription" -string "The camera is needed to scan QR codes" -- ${infoplist}
fi

if [ -d overrides/ ]; then
	echo ""
	echo "Applying overrides..."
	echo ""
	(cd overrides && cp -fpvR * ../iOS/ && cd ..)
fi

patches=patches/*.patch
if [ -n "$patches" ]; then
	echo ""
	echo "Applying patches..."
	echo ""
	for p in $patches; do
		[ -e $p ] && patch -p 1 < $p
	done
fi

# Get latest rubicon with all the patches from Github
echo ""
echo "Updating rubicon-objc to latest from cculianu repository on github..."
echo ""
[ -e scratch ] && rm -fr scratch
mkdir -v scratch || exit 1
cd scratch || exit 1
git clone http://www.github.com/fyookball/rubicon-objc
gitexit="$?"
cd rubicon-objc
git checkout send_super_fix
gitexit2="$?"
cd ..
cd ..
[ "$gitexit" != "0" -o "$gitexit2" != 0 ] && echo '*** Error crabbing the latest rubicon off of github' && exit 1
rm -fr iOS/app_packages/rubicon/objc
cp -fpvr scratch/rubicon-objc/rubicon/objc iOS/app_packages/rubicon/ 
[ "$?" != "0" ] && echo '*** Error copying rubicon files' && exit 1
rm -fr scratch

xcode_file="Electron-Cash.xcodeproj/project.pbxproj" 
echo ""
echo "Mogrifying Xcode .pbxproj file to use iOS 9.0 deployment target..."
echo ""
sed  -E -i original 's/(.*)IPHONEOS_DEPLOYMENT_TARGET = [0-9.]+(.*)/\1IPHONEOS_DEPLOYMENT_TARGET = 9.0\2/g' "iOS/${xcode_file}"
if [ "$?" != 0 ]; then
	echo "Error modifying Xcode project file iOS/$xcode_file... aborting."
	exit 1
else
	echo ".pbxproj mogrifid ok."
fi

echo ""
echo "Adding HEADER_SEARCH_PATHS to Xcode .pbxproj..."
echo ""
python3 -m pbxproj flag iOS/Electron-Cash.xcodeproj/project.pbxproj -- HEADER_SEARCH_PATHS '"$(SDK_DIR)"/usr/include/libxml2'
if [ "$?" != 0 ]; then
	echo "Error adding libxml2 to HEADER_SEARCH_PATHS... aborting."
	exit 1
fi

resources=Resources/*
if [ -n "$resources" ]; then
	echo ""
	echo "Adding Resurces/ and CustomCode/ to project..."
	echo ""
	cp -fRav Resources CustomCode iOS/
	(cd iOS && python3 -m pbxproj folder -r "${xcode_file}" Resources)
	if [ "$?" != 0 ]; then
		echo "Error adding Resources to iOS/$xcode_file... aborting."
		exit 1
	fi
	(cd iOS && python3 -m pbxproj folder -r "${xcode_file}" CustomCode)
	if [ "$?" != 0 ]; then
		echo "Error adding CustomCode to iOS/$xcode_file... aborting."
		exit 1
	fi
fi

echo ''
echo '**************************************************************************'
echo '*                                                                        *'
echo '*   Operation Complete. An Xcode project has been generated in "iOS/"    *'
echo '*                                                                        *'
echo '**************************************************************************'
echo ''
echo '  IMPORTANT!'
echo '        Now you need to manually add AVFoundation and libxml2.tbd to the '
echo '        project Frameworks else you will get build errors!'
echo ''
echo '  Also note:'
echo '        Modifications to files in iOS/ will be clobbered the next    '
echo '        time this script is run.  If you intend on modifying the     '
echo '        program in Xcode, be sure to copy out modifications from iOS/ '
echo '        manually or by running ./copy_back_changes.sh.'
echo ''
