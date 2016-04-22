Peershares development process
==============================

Development is divided into "phases".

Each phase is a new set of features and is described in a GitHub issue. The phase issues have a "phase" label.

A new label "phase N" (where N is the number of the phase) is created and put on the phase issue. If the phase is divided in other tasks, each one also has the "phase N" label.

The main channel to discuss the tasks is on the corresponding GitHub issue.

A minor version is associated to each phase. For example 0.2.0 for phase 2. This branch is based on the master branch.

When a developer works on a phase, he pushes his changes to a new branch on his own fork of Peershares (he's free to choose the name of the branch, but using the phase branch name makes it easier). He then makes a pull request from his branch to the current phase branch on Peershares' repository.
Jordan (or anyone he assigned) will merge the pull request or close it.

If at any time we think we must drop commits from the phase branch a start with different history, we create a new phase branch with a new patch number (for example 0.2.1). All pending and new pull requests must be made to this new branch.
We never force a push on Peershares' repository.

If changes occur on the master branch in the meantime, they can be merged into the phase branch. But we do not merge commits from another phase that were not merged into master.

When the phase seems ready, a new pull request is created from the latest phase branch to the master branch (Warning: GitHub will think you want to make a pull request on Peercoin's repository, you must change it to Peershares). Testers are notified and they must get the branch mentioned in the pull request. The release is discussed in the issue opened by the pull request.

