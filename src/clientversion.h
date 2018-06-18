#ifndef CLIENTVERSION_H
#define CLIENTVERSION_H

#if defined(HAVE_CONFIG_H)
#include "bitcoin-config.h"
#else
//
// client versioning and copyright year
//

// These need to be macros, as version.cpp's and bitcoin-qt.rc's voodoo requires it
#define CLIENT_VERSION_MAJOR       0
#define CLIENT_VERSION_MINOR       8
#define CLIENT_VERSION_REVISION    6
#define CLIENT_VERSION_BUILD       0

// Set to true for release, false for prerelease or test build
#define CLIENT_VERSION_IS_RELEASE  true

// Copyright year (2009-this)
// Todo: update this when changing our copyright comments in the source
#define COPYRIGHT_YEAR 2013

#endif //HAVE_CONFIG_H

// ppcoin version - intended for display purpose ONLY
#define SPROUTS_VERSION_MAJOR       0
#define SPROUTS_VERSION_MINOR       2
#define SPROUTS_VERSION_REVISION    0
#define SPROUTS_VERSION_BUILD       0

// Copyright year (2009-this)
// Todo: update this when changing our copyright comments in the source
#define COPYRIGHT_YEAR 2018

// Converts the parameter X to a string after macro replacement on X has been performed.
// Don't merge these into one macro!
#define STRINGIZE(X) DO_STRINGIZE(X)
#define DO_STRINGIZE(X) #X

#endif // CLIENTVERSION_H
