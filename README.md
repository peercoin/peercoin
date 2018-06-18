
Sprouts Official Development Repo
==================================

[![Build Status](https://travis-ci.org/sprouts/sprouts.svg?branch=master)](https://travis-ci.org/sprouts/sprouts)

### What is Sprouts?

Sprouts is a Sprouts network-compatible, community-developed wallet client.

The project has been designed to provide people with a stable, secure, and feature-rich alternative to the Sprouts reference wallet (http://github.com/ppcoin/ppcoin).

To help faciliate broad community cooperation, a number of trusted Sprouts/Peershares community leaders have write permissions to the project's codebase, allowing for decentralization and continuity. Community members, old and new, are encouraged to find ways to contribute to the success of the project. If you have experience with programming, product design, QA engineering, translation, or have a different set of skills that you want to bring to the project, your involvement is appreciated!

### Sprouts Resources
* Source: [Source Code](https://github.com/Sprouts/Sprouts)
* Documentation: [Build Instructions](https://github.com/Sprouts/Sprouts/tree/master/doc)

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test. Please be patient and help out, and
remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write unit tests for new code, and to
submit new unit tests for old code.

Unit tests can be compiled and run (assuming they weren't disabled in configure) with:
  make check

Every pull request is built for both Windows and Linux on a dedicated server,
and unit and sanity tests are automatically run. The binaries produced may be
used for manual QA testing — a link to them will appear in a comment on the
pull request posted by [BitcoinPullTester](https://github.com/BitcoinPullTester). See https://github.com/TheBlueMatt/test-scripts
for the build/test scripts.

### Manual Quality Assurance (QA) Testing

Large changes should have a test plan, and should be tested by somebody other
than the developer who wrote the code.

* Developers work in their own forks, then submit pull requests when they think their feature or bug fix is ready.
* If it is a simple/trivial/non-controversial change, then one of the development team members simply pulls it.
* The patch will be accepted if there is broad consensus that it is a good thing. Developers should expect to rework and resubmit patches if they don't match the project's coding conventions (see coding.txt) or are controversial.
* From time to time a pull request will become outdated. If this occurs, and the pull is no longer automatically mergeable; a comment on the pull will be used to issue a warning of closure.  Pull requests closed in this manner will have their corresponding issue labeled 'stagnant'.

## Branches:

### develop (all pull requests should go here)
The develop branch is used by developers to merge their newly implemented features to.
Pull requests should always be made to this branch (except for critical fixes), and could possibly break the code.
The develop branch is therefore unstable and not guaranteed to work on any system.

### master (only updated by group members)
The master branch get's updates from tested states of the develop branch.
Therefore, the master branch should contain functional but experimental code.

### release-* (the official releases)
The release branch is identified by it's major and minor version number e.g. `release-0.6`.
The official release tags are always made on a release branch.
Release branches will typically branch from or merge tested code from the master branch to freeze the code for release.
Only critical patches can be applied through pull requests directly on this branch, all non critical features should follow the standard path through develop -> master -> release-*
