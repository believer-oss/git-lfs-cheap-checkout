# git-lfs-cheap-checkout

During the git-lfs fetch files are downloaded to the LFS storage location, typically `.git/lfs/objects`, and then moved into the working directory during checkout. On a filesystem that supports copy-on-write this is a fast operation, but filesystems that do not support copy-on-write fallback to copying bytes. This is discussed further in [git-lfs issue #3450](https://github.com/git-lfs/git-lfs/issues/3450) and the objections in the thread are absolutely correct for the general case.

> [!CAUTION]
> This should only be used where the system cannot push changes to the repository.

For systems that can ensure that no changes will be later pushed to the repository, this can be used in place of the checkout process to avoiding the fallback by creating a hard link to the file. The only scenario this has seen significant usage is on a Windows CI/CD system where no modifications would take place after the checkout.
