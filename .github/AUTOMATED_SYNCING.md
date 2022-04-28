# Automated Syncing

This repo makes automated syncing of upstream (OSS source) projects easy.
We aim to solve some common problems when leveraging and contributing to OSS projects:

* local branches/PRs fall behind upstream project commits
* a high-touch file like the top-level README leads to "merge hell" where you
  must manually merge over and over for each commit that modified the README
* long delays in merging desireable PRs in to the upstream project

If you are an individual contributor to an OSS project then a simple fork (upstream-mirror) repo is all you need. The main benefit automated sync will
add is automatically keeping your PRs updated on the latest changes and 
automatically creating a "fixup" branch that pulls in any upstream PRs not 
yet merged which you desire. 

If you are a team at a company, and especially if you have a highly customized fork, 
then you may want to consider the PRIVATE_TO_PUBLICH_REPO.md strategy which is
especially helpful if your fork is private and you still want to contribute upstream.
In this case, you create two repos, ACTIVE_GIT_REPO (private) for the messy 
fork and UPSTREAM_MIRROR_GIT_REPO (public) to make upstream PRs.

The default branch is usually named "main" or "master". We will assume "main".
The repos and their automated branches differ from upstream as follows:

## UPSTREAM_GIT_ORG Repo
The official OSS git repo. It doesn't make sense to have auto-syncing here
since it has nothing to sync to.

## UPSTREAM_MIRROR_GIT_ORG Repo
The public mirror or upstream used to make PRs. The "main" branch in this
repo differs from upstream by the following files:
* .github/AUTOMATED_SYNCING.md
* .github/git_sync.sh
* .github/workflows/sync.yml

When git_sync.sh runs, it will create a branch called `upstream-main`.

The `upstream-main` branch is pristine replica of `upstream/main`.

Branch off of upstream-master for features you intened to merge upstream.
Make updates to `main` for things like using gitleaks to ensure that secrets 
or corporate info does not get included in an upstream PR.

## ACTIVE_GIT_ORG Repo
The `main` branch will have the .github/ differences above and any commits related
to the customization of your fork.

If there are files in `PULL_REQUEST_BRANCHES`, a `main-fixup` branch will
be created. Currently git_sinc.sh allows `main` and `main-fixup` to diverge.
You could modify it to initialize `main-fixup` from `origin/main` and then
pull in `upstream-main-fixup`. 

If there are files in .gitattributes these generate MERGE_CONFLICT_FILES.
Check if these any files to be merged in are in MERGE_CONFLICT_FILES and
send an alert if so.

## What git_sync.sh does

We want to make this really frictionless, so we must keep in sync as much as possible.
This involves both the remote forked repos, and the local branches on a developer 
machine. 

* If git_sync.sh is run on a mac, it sets up a cron job to update
the current repo daily with the --local-only flag so it doesn't push to origin.
* If run in a github runner, it sets updates the remote origin repo.

The following branches are created/updated:

* upstream-main       - always pristing replica of upstream/main
* main                - merged of upstream/main is attempted, alert if not possible

Sometimes, when project owners are a bit slow to handle PRs, you may find that
you need one or several PRs for your current work. git_sync.sh uses the 
following vaariables 

```
PULL_REQUEST_BRANCHES - any PRs not yet merged that you need for your deployment
MERGE_CONFLICT_FILES  - if these files change in upstream there will be a merge 
                        conflict (because you changed them too).  This is a
                        space-separated-list generated from .gitattributes 
```

The following branches are updated/created:

* upstream-$feature         - pristine copy of each $feature in PULL_REQUEST_BRANCHES
* upstream-main-fixup       - combined merge of all upstream-$feature branches
                              use this if creating a PR for upstream
* main-fixup                - merge upstream-main-fixup into main-fixup. You can 
                              choose if you want to merge this into main, or keep
                              them distinct for debugging.

## Merge Conflicts

We use `.gitattributes` to specify files which we won't try to merge from uptstream,
such as the top-level README.md. Then run the following command.
```
git config --global merge.ours.driver true
MERGE_CONFLICT_FILES=`cat .gitattributes | cut -d' ' -f1`
```

## Quick Start: New User Repo Bootstrapping

```
git clone https://github.com/$GIT_ORG/$COMPANY-panther-analysis.git
git clone https://github.com/$GIT_ORG/panther-analysis.git
```

## One-Time Repo Bootstrapping Active Fork of Upstream

Source the following into your environment.
```
UPSTREAM_GIT_ORG="$GIT_ORG"
ACTIVE_GIT_ORG="$GIT_ORG"
UPSTREAM_MIRROR_GIT_ORG="$COMPANY"
REPO="panther-analysis"
ACTIVE_REPO="$COMPANY-panther-analysis"
# Branches
UPSTREAM_BASE_BRANCH="master" # usually master or main
ACTIVE_BASE_BRANCH="master"
```

After creating an empty `REPO` in `ACTIVE_GIT_ORG`,  
```
# Clone the private_to_putlic repo which has sync.yml and git_sync.sh
git clone https://github.com/kbroughton/private_to_public_repo.git
git clone https://github.com/panther-labs/panther-analysis.git
cp private_to_public_repo/git_sync.sh panther-analysis/.github/
chmod a+x .github/git_sync.sh
cp private_to_public_repo/.github/workflows/sync.yml panther-analysis/.github/workflow/sync.yml
cd panther-analysis
# Change origin to point to our new
git remote add upstream https://github.com/panther-labs/panther-analysis.git
git remote remove origin
git remote add origin git@github.com:$GIT_ORG/$COMPANY-panther-analysis.git
git branch -M master
git push -u origin master
git status
git add .
git commit -m "add git_sync.sh and sync.yml action"

## Syncing Remotes
* [Github Action Cron Trigger](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#schedule)


Github actions are performed on a github runner from within the 
repo hosting the action.
Syncing the upstream-mirror repo is easy as it only differs from upstream
when we create a pull request from a branch in the customized (active) repo.
Syncing for the active repo is as follows:

* sync the upstream remote updating local main branch (UPSTREAM_BASE_BRANCH)
* merge the update to upstream-main and push to this repo's origin
* attempt to merge in all PULL_REQUEST_BRANCHES to upstream-main-fixup
* work off of upstream-main-fixup in general
* make upstream PRs based off of upstream-main

Modify git_sync.config as needed.
```
./.github/git_sync.sh
```

Set up the active repo and upstream-mirror for github actions.


At the end of the day we get this
* $GIT_ORG/$COMPANY-panther-analysis:upstream-master 
    - is identical to panther-labs/panther-analysis:master
* $GIT_ORG/$COMPANY-panther-analysis:upstream-master-fixup
    - is upstream-master with PULL_REQUEST_BRANCHES merged in
* $GIT_ORG/$COMPANY-panther-analysis:master
    - has custom commits and potential upstream PRs with 
      upstream-master-fixup merged in but MERGE_CONFLICT_FILES ignored

If files in MERGE_CONFLICT_FILES need to be merged in, we should generate
an alert or create a Jira ticket automatically.

## Syncing Locals
* [Mac Crontab](https://ole.michelsen.dk/blog/schedule-jobs-with-crontab-on-mac-osx/)
  crontab -e `0 12 * * *  cd ~/my/backup/folder && ./backup.sh`

## Alternative Approaches

### Ephemeral upstream-mirror
A completely valid alternative would be to create the upstream-mirror
ephemerally for every upstream PR. However, with a curated upstream-mirror,
we can enforce code-quality and conventions and maintain a record of 
activity more easily.

### Detecting Remote Changes

* [Polling for change and triggering](https://github.com/cloudbase/gitpoll/blob/master/sample.config)
