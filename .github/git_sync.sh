#!/bin/bash

set -ex

cat<<EOF
USAGE: ./.github/git_sync.sh [--local-only] if --local-only do not push to remotes

If run on a mac, it will set up a crontab job to run this script every day.
BE SURE YOU TRUST THE REPO YOU ARE SYNCING WITH as modifications to git_sync.sh
or files in .github/ actions could have security implications.

This script is used to sync the default branch of an OSS "upstream" repo
to a branch called upstream/<default> in the active/current repo.
If a file named PULL_REQUEST_BRANCHES is found in the current repo
then the branches listed in that file will be merged into the 
upstream/<default>-fixup branch. The fixup branch will then be merged 
into the local <default> branch.

The following branches are synced or created (assuming <default> = main):
* upstream-main - this is identical to the upstream/main branch
* main          - attempt to merge in upstream/main ignoring files in .gitattributes

If there is a PUll_REQUEST_BRANCHES file in the current repo then these are synced or created:
* upstream-feature    - for each feature branch listed in the PULL_REQUEST_BRANCHES file
* upstream-main-fixup - sunc upstream/main and PRs from upstream's PULL_REQUEST_BRANCHES
* main-fixup          - attempt to merge in upstream main and PUll_REQUEST_BRANCHES ignoring files in .gitattributes
EOF

if [[ $OSTYPE == "darwin"* ]]; then
    # MacOS
    crontab -l > /tmp/crontab || true
    if [[ x`grep git_sync /tmp/crontab || true`x == "xx" ]]; then
        echo "Setting up crontab for git_sync"
        cp ./.github/git_sync.sh /usr/local/bin/git_sync
        chmod a+x /usr/local/bin/git_sync
        echo "0 13 * * *  && git_sync --local-only" >> /tmp/crontab
        crontab</tmp/crontab
    else
        echo "git_sync already setup in crontab, updating /usr/local/bin/git_sync"
        cp ./.github/git_sync.sh /usr/local/bin/git_sync
        chmod a+x /usr/local/bin/git_sync
    fi
    rm /tmp/crontab 
fi

if [[ -f "./.github/git_sync.config" ]]; then
    echo "Using values in git_sync.config"
    source ./.github/git_sync.config
else
    echo "Using hard-coded values in git_sync.sh"
    COMPANY="CHANGE_ME"
    # ORGs
    UPSTREAM_GIT_ORG="panther-labs"
    ACTIVE_GIT_ORG="CHANGE_ME"
    UPSTREAM_MIRROR_GIT_ORG="CHANGE_ME"
    # REPOs
    REPO="panther-analysis"
    ACTIVE_REPO="$COMPANY-panther-analysis"
    # Branches
    UPSTREAM_BASE_BRANCH="master" # usually master or main
    ACTIVE_BASE_BRANCH="master"
    USER_EMAIL="GIT_SYNC_ACTION@dummy.com"
    USER_NAME="GIT SYNC ACTION"
fi

git config --global user.email "${USER_EMAIL}"
git config --global user.name "${USER_NAME}"
git config --global core.mergeoptions --no-edit
# If there is a merge conflict with files in .gitattributes, keep ours
git config --global merge.ours.driver true

if [[ -f .gitattributes ]]; then
    # Note that .gitattributes allows lots of .gitignore patterns
    # We currently only support full file path names when checking
    # if a file is a merge conflict with the incoming PR.
    cat .gitattributes | cut -d' ' -f1 | sort > /tmp/MERGE_CONFLICT_FILES
else
    echo "" > /tmp/MERGE_CONFLICT_FILES
fi

if [[ $1 == "--local-only" ]]; then
    echo "--local-only option specified, not pushing to remotes"
    IS_LOCAL_ONLY=true
else
    IS_LOCAL_ONLY=false
fi


# Update all remote branch references. This does not pull all branches locally.
upstream_exists=`git remote | grep '^upstream$' || true`
if [[ ${upstream_exists} == "upstream" ]]; then
    echo "Upstream remote already exists"
else
    echo "Setting up remote upstream"
    git remote add upstream https://github.com/${UPSTREAM_GIT_ORG}/${REPO}.git
fi    
git fetch upstream 


function merge_and_alert() {
    # This function assumes we are on the branch we wish to merge into.
    # Start the merge from upstream/master without changing the working tree.
    LOCAL_MERGE_BRANCH=$1
    REMOTE_BRANCH=$2

    branch_commit=`git rev-parse -q --verify ${LOCAL_MERGE_BRANCH} || echo ""`
    if [[ x${branch_commit}x == "xx" ]]; then
        echo "Local branch ${LOCAL_MERGE_BRANCH} does not exist, creating"
        git switch -c ${LOCAL_MERGE_BRANCH} upstream/${REMOTE_BRANCH}
    else
        echo "Local branch ${LOCAL_MERGE_BRANCH} already exists, updating"
        git switch ${LOCAL_MERGE_BRANCH}
    fi
    git merge --no-edit --no-commit upstream/$REMOTE_BRANCH

    # Check if there are any merge conflicts with files in .gitattributes
    git diff --cached --name-only | sort > /tmp/GIT_DIFF_CACHED
    cached=`cat /tmp/GIT_DIFF_CACHED`
    # Do a join (like in sql) to find the files that are in both
    intersection=`join /tmp/GIT_DIFF_CACHED /tmp/MERGE_CONFLICT_FILES`
    if [[ x${interserction}x != "xx" ]]; then
        echo "TODO: create an alert"
    fi
    # Commit merge, but keep ours if files are in .gitattributes
    # This could still fail if there are upstream and local changes to
    # the same files. But in that case, update .gitattributes and try again.
    if [[ x${cached}x != "xx" ]]; then
        git merge --continue
    else
        echo "Nothing to commit"
    fi

    # Only push if we are allowed and there is something to push
    if [[ ${IS_LOCAL_ONLY} = false ]]; then \
        git push --force --set-upstream origin ${LOCAL_MERGE_BRANCH}
    fi
}

# Merge upstream/master into the upstream-master branch
# This should always be an exact replica.
merge_and_alert upstream-master $UPSTREAM_BASE_BRANCH


if [[ -s PULL_REQUEST_BRANCHES ]]; then
    pull_request_branches=`cat PULL_REQUEST_BRANCHES`
    echo "Pull request branches: ${pull_request_branches[@]}"
    # If there are PULL_REQUEST_BRANCHES then prepare the pristine uspstream-master-fixup branch.
    # It starts off as upstream-master. Only bother if we have PRs to merge.
    merge_and_alert upstream-${UPSTREAM_BASE_BRANCH}-fixup ${UPSTREAM_BASE_BRANCH}

else
    pull_request_branches=""
fi

## Often due to delays in merging PRs we will need to pull in some PRs.
## Create PULL_REQUEST_BRANCHES individually in case we need them for debugging.
for feature in ${pull_request_branches[@]}; do
    # branch_commit_hash is empty if the branch does not exist
    branch_commit_hash=`git rev-parse -q --verify upstream-$feature || echo ""`
    if [[ x${branch_commit_hash}x != "xx" ]]; then
        # We should not be making any local changes to PULL_REQUEST_BRANCHES
        # and if we did, it would require -D to force and this would fail.
        git branch -d upstream-${feature}
    fi
    # Refresh the PR in our repo origin/feature from upstream/feature
    merge_and_alert ${feature} ${feature}

    ## We will start new work by branching off of fixup branch if it exists.
    ## Merge in each PULL_REQUEST_BRANCHES to upstream-${UPSTREAM_BASE_BRANCH}-fixup 
    ## skipping over files in MERGE_CONFLICT_FILES

    ## Update the pristine upstream-master-fixup branch which we prepared above.
    #git switch upstream-${UPSTREAM_BASE_BRANCH}-fixup
    merge_and_alert upstream-${UPSTREAM_BASE_BRANCH}-fixup ${feature} 

    # Create the fixup branch if it does not exist 
    merge_and_alert ${UPSTREAM_BASE_BRANCH}-fixup ${feature}

done

# Only push upstream-master-fixup and master-fixup once we are done with all the PRs.
# if [[  ${IS_LOCAL_ONLY} = false && x${PULL_REQUEST_BRANCHES}x != "xx" ]]; then
#     git push origin ${UPSTREAM_BASE_BRANCH}-fixup --set-upstream origin ${UPSTREAM_BASE_BRANCH}-fixup
#     git push origin upstream-${UPSTREAM_BASE_BRANCH}-fixup --set-upstream origin upstream-${UPSTREAM_BASE_BRANCH}-fixup
# fi

# Finally, merge in upstream/master to local origin/master.
merge_and_alert master $UPSTREAM_BASE_BRANCH