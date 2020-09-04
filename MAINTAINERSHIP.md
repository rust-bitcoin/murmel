Maintainers agree to operate under this set of guidelines:

#### Authority

Maintainers are trusted to close issues, merge pull requests, and publish crates to cargo.

#### Categories of Work

0. Changelog
    * updating CHANGELOG.md
    * requires no approval
1. Minor
    * changing an existing dependency to a new minor version
    * fixes and enhancements that do not change public or private APIs and control flows
    * changes to CI or other build tools or to documentation
    * minor murmel releases to crates.io that contain only the above work
    * require 1 approval from another maintainer. if no maintainer is able to be reached for 2 weeks, then progress may be made anyway
2. Major
    * adding a new dependency or changing an existing dependency to a new major version 
    * refactoring, which should generally only be done for clearly functional reasons like to aid in the completion of a specific task
    * require consensus among all maintainers unless 2 weeks have gone by without full participation
    * if 2 weeks have gone by after seeking feedback, and at least one other maintainer has participated, and all participating maintainers are in agreement, then progress may be made anyway
    * if action is absolutely urgent, an organization owner may act as a tiebreaker if specifically requested to do so and they agree that making a controversial decision is worth the risk. This should hopefully never occur.
  
If any maintainer thinks an issue is major, it is major.

#### Changelog Maintenance

* If you are the one who merges a PR that includes an externally-visible change, please describe the change in the changelog and merge it in.

#### Releasing, Publishing

* Releases adhere to [semver](https://semver.org/)
* To cut a release, an issue should be opened for it and reach the required approval based on the above `Categories of Work` section above
* When progress is possible, the issue may be closed and the proposer may publish to crates.io. This is controlled by those in the [murmel crate publishers organization-level team](https://github.com/orgs/rust-bitcoin/teams/murmel-crate-publishers).
* Releases should have an associated tag pushed to this repo. I recommend doing this after the publish to crates.io succeeds to prevent any mishaps around pushing a tag for something that can't actually be published.
* The changelog serves as a sort of logical staging area for releases
* If a breaking API change happens, and the changelog has not advanced to a new major version, we roll the changelog to a new major version and open an issue to release the previous patch (and post-1.0, minor) version.
* Before rolling to a new major version, it would be nice to release a non-breaking point release to let current users silently take advantage of any improvements

#### Becoming a Maintainer

* If you have a history of participation in this repo, agree to these rules, and wish to take on maintainership responsibilities, you may open an issue. If an owner agrees, they will add you to the maintainer group and the murmel crate publishers team.

#### Attribution

This document was adapted from the [MAINTAINERSHIP.md](https://github.com/rust-rocksdb/rust-rocksdb/blob/master/MAINTAINERSHIP.md) 
file for the [rust-rocksdb](https://github.com/rust-rocksdb/rust-rocksdb) project.