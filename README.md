# Peercoin Official Development Repo

[![Peercoin Donate](https://badgen.net/badge/peercoin/Donate/green?icon=https://raw.githubusercontent.com/peercoin/media/84710cca6c3c8d2d79676e5260cc8d1cd729a427/Peercoin%202020%20Logo%20Files/01.%20Icon%20Only/Inside%20Circle/Transparent/Green%20Icon/peercoin-icon-green-transparent.svg)](https://blockbook.peercoin.net/address/p92W3t7YkKfQEPDb7cG9jQ6iMh7cpKLvwK)
[![Continuous Integration](https://github.com/peercoin/peercoin/actions/workflows/build.yml/badge.svg?branch=master)](https://github.com/peercoin/peercoin/actions/workflows/build.yml)

### What is Peercoin?
[Peercoin](https://peercoin.net) (abbreviated PPC), previously known as PPCoin, is the first [cryptocurrency](https://en.wikipedia.org/wiki/Cryptocurrency) design introducing [proof-of-stake consensus](https://peercoin.net/resources#whitepaper) as a security model, with a combined [proof-of-stake](https://peercoin.net/resources#whitepaper)/[proof-of-work](https://en.wikipedia.org/wiki/Proof-of-work_system) minting system. Peercoin is based on [Bitcoin](https://bitcoin.org), while introducing many important innovations to cryptocurrency field including new security model, energy efficiency, better minting model and more adaptive response to rapid change in network computation power.
### Peercoin Resources
* Client and Source:
[Client Binaries](https://github.com/peercoin/peercoin/releases),
[Source Code](https://github.com/peercoin/peercoin)
* Documentation: [Peercoin Docs](https://docs.peercoin.net)
* Help: 
[Forum](https://talk.peercoin.net),
[Intro & Important Links](https://talk.peercoin.net/t/what-is-peercoin-intro-important-links/2889),
[Telegram Chat](https://t.me/peercoin)

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test. Please be patient and help out, and
remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write unit tests for new code, and to submit new unit tests for old code.

Unit tests can be compiled and run (assuming they weren't disabled in configure) with:
  make check

### Manual Quality Assurance (QA) Testing

Large changes should have a test plan, and should be tested by somebody other than the developer who wrote the code.

* Developers work in their own forks, then submit pull requests when they think their feature or bug fix is ready.
* If it is a simple/trivial/non-controversial change, then one of the development team members simply pulls it.
* If it is a more complicated or potentially controversial change, then the change may be discussed in the pull request, or the requester may be asked to start a discussion in the [Peercoin Forum](https://talk.peercoin.net) for a broader community discussion. 
* The patch will be accepted if there is broad consensus that it is a good thing. Developers should expect to rework and resubmit patches if they don't match the project's coding conventions (see coding.txt) or are controversial.
* From time to time a pull request will become outdated. If this occurs, and the pull is no longer automatically mergeable; a comment on the pull will be used to issue a warning of closure.  Pull requests closed in this manner will have their corresponding issue labeled 'stagnant'.
* For development ideas and help see [here](https://talk.peercoin.net/c/protocol).

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


