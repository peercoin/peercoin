
Peercoin Official Development Repo
==================================

### What is Peercoin (PPCoin)?
[Peercoin](http://peercoin.net/) (abbreviated PPC), also known as PPCoin and Peer-to-Peer Coin is the first [cryptocurrency](https://en.wikipedia.org/wiki/Cryptocurrency) design introducing [proof-of-stake consensus](http://peercoin.net/bin/peercoin-paper.pdf) as a security model, with a combined [proof-of-stake](http://peercoin.net/bin/peercoin-paper.pdf)/[proof-of-work](https://en.wikipedia.org/wiki/Proof-of-work_system) minting system. Peercoin is based on [Bitcoin](http://bitcoin.org/en/), while introducing many important innovations to cryptocurrency field including new security model, energy efficiency, better minting model and more adaptive response to rapid change in network computation power.

### Peercoin Resources
* Client and Source:
[Client Binaries](http://sourceforge.net/projects/ppcoin/files/),
[Source Code](https://github.com/ppcoin/ppcoin)
* Documentation: [Peercoin Whitepaper](http://peercoin.net/bin/peercoin-paper.pdf),
[Peercoin Wiki](https://github.com/ppcoin/ppcoin/wiki)
* Help: 
[Forum](http://www.peercointalk.org/),
[Other Sites and Links...](http://www.peercointalk.org/index.php?topic=4.0;topicseen)

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
* If it is a more complicated or potentially controversial change, then the change may be discussed in the pull request, or the requester may be asked to start a discussion [Peercoin Talk](http://www.peercointalk.org/) for a broader community discussion. 
* The patch will be accepted if there is broad consensus that it is a good thing. Developers should expect to rework and resubmit patches if they don't match the project's coding conventions (see coding.txt) or are controversial.
* From time to time a pull request will become outdated. If this occurs, and the pull is no longer automatically mergeable; a comment on the pull will be used to issue a warning of closure.  Pull requests closed in this manner will have their corresponding issue labeled 'stagnant'.
* For development ideas and help see [here](http://www.peercointalk.org/index.php?board=10.0).
