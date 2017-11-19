/*fs/namespace.c*/
/**
dev_name:proc dir_name:/proc type_page:proc flags:8000
dev_name:tmpfs dir_name:/tmp type_page:tmpfs flags:8000
dev_name:sysfs dir_name:/sys type_page:sysfs flags:8000
dev_name:tmpfs dir_name:/dev type_page:tmpfs flags:8000
dev_name:devpts dir_name:/dev/pts type_page:devpts flags:8000
dev_name:debugfs dir_name:/sys/kernel/debug type_page:debugfs flags:8000
*/
SYSCALL_DEFINE5(mount, char __user *, dev_name, char __user *, dir_name,
		char __user *, type, unsigned long, flags, void __user *, data)
{
	int ret;
	char *kernel_type;
	char *kernel_dev;
	unsigned long data_page;

	kernel_type = copy_mount_string(type);

	kernel_dev = copy_mount_string(dev_name);

	ret = copy_mount_options(data, &data_page);

	ret = do_mount(kernel_dev, dir_name, kernel_type, flags,
		(void *) data_page);

	free_page(data_page);
out_data:
	kfree(kernel_dev);
out_dev:
	kfree(kernel_type);
out_type:
	return ret;
}


struct filename {
	const char		*name;	/* pointer to actual string */
	const __user char	*uptr;	/* original userland pointer */
	struct audit_names	*aname;
	int			refcnt;
	bool			separate; /* should "name" be freed? */
};

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

struct nameidata {
	struct path	path;
	struct qstr	last;
	struct path	root;
	struct inode	*inode; /* path.dentry.d_inode */
	unsigned int	flags;
	unsigned	seq, m_seq;
	int		last_type;
	unsigned	depth;
	struct file	*base;
	char *saved_names[MAX_NESTED_LINKS + 1];
};

struct fs_struct {
	int users;
	spinlock_t lock;
	seqcount_t seq;
	int umask;
	int in_exec;
	struct path root, pwd;
};


/*
 * Old magic mount flag and mask
 */
#define MS_MGC_VAL 0xC0ED0000
#define MS_MGC_MSK 0xffff0000

#define AT_FDCWD		-100    /* Special value used to indicate
                                           openat should use the current
                                           working directory. */

/*
 * The bitmask for a lookup event:
 *  - follow links at the end
 *  - require a directory
 *  - ending slashes ok even for nonexistent files
 *  - internal "there are more path components" flag
 *  - dentry cache is untrusted; force a real lookup
 *  - suppress terminal automount
 */
#define LOOKUP_FOLLOW		0x0001
#define LOOKUP_DIRECTORY	0x0002
#define LOOKUP_AUTOMOUNT	0x0004

#define LOOKUP_PARENT		0x0010
#define LOOKUP_REVAL		0x0020
#define LOOKUP_RCU		0x0040

/*
 * Intent data
 */
#define LOOKUP_OPEN		0x0100
#define LOOKUP_CREATE		0x0200
#define LOOKUP_EXCL		0x0400
#define LOOKUP_RENAME_TARGET	0x0800

#define LOOKUP_JUMPED		0x1000
#define LOOKUP_ROOT		0x2000
#define LOOKUP_EMPTY		0x4000



#define user_path(name, path) user_path_at(AT_FDCWD, name, LOOKUP_FOLLOW, path)


long do_mount(const char *dev_name, const char __user *dir_name,
		const char *type_page, unsigned long flags, void *data_page)
{
	struct path path;
	int retval = 0;
	int mnt_flags = 0;


	/* Discard magic */
	if ((flags & MS_MGC_MSK) == MS_MGC_VAL)
		flags &= ~MS_MGC_MSK;

	/* Basic sanity checks */
	if (data_page)
		((char *)data_page)[PAGE_SIZE - 1] = 0;

	/* ... and get the mountpoint */
	retval = user_path(dir_name, &path);
	if (retval)
		return retval;

	retval = security_sb_mount(dev_name, &path,
				   type_page, flags, data_page);
	if (!retval && !may_mount())
		retval = -EPERM;
	if (retval)
		goto dput_out;

	/* Default to relatime unless overriden */
	if (!(flags & MS_NOATIME))
		mnt_flags |= MNT_RELATIME;

	/* Separate the per-mountpoint flags */
	if (flags & MS_NOSUID)
		mnt_flags |= MNT_NOSUID;
	if (flags & MS_NODEV)
		mnt_flags |= MNT_NODEV;
	if (flags & MS_NOEXEC)
		mnt_flags |= MNT_NOEXEC;
	if (flags & MS_NOATIME)
		mnt_flags |= MNT_NOATIME;
	if (flags & MS_NODIRATIME)
		mnt_flags |= MNT_NODIRATIME;
	if (flags & MS_STRICTATIME)
		mnt_flags &= ~(MNT_RELATIME | MNT_NOATIME);
	if (flags & MS_RDONLY)
		mnt_flags |= MNT_READONLY;

	/* The default atime for remount is preservation */
	if ((flags & MS_REMOUNT) &&
	    ((flags & (MS_NOATIME | MS_NODIRATIME | MS_RELATIME |
		       MS_STRICTATIME)) == 0)) {
		mnt_flags &= ~MNT_ATIME_MASK;
		mnt_flags |= path.mnt->mnt_flags & MNT_ATIME_MASK;
	}

	flags &= ~(MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_ACTIVE | MS_BORN |
		   MS_NOATIME | MS_NODIRATIME | MS_RELATIME| MS_KERNMOUNT |
		   MS_STRICTATIME);

	if (flags & MS_REMOUNT)
		retval = do_remount(&path, flags & ~MS_REMOUNT, mnt_flags,
				    data_page);
	else if (flags & MS_BIND)
		retval = do_loopback(&path, dev_name, flags & MS_REC);
	else if (flags & (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE))
		retval = do_change_type(&path, flags);
	else if (flags & MS_MOVE)
		retval = do_move_mount(&path, dev_name);
	else
		retval = do_new_mount(&path, type_page, flags, mnt_flags,
				      dev_name, data_page);
dput_out:
	path_put(&path);
	return retval;
}

int user_path_at(int dfd, const char __user *name, unsigned flags,
		 struct path *path)
{
	return user_path_at_empty(dfd, name, flags, path, NULL);
}

/*flags=LOOKUP_FOLLOW empty=NULL*/
int user_path_at_empty(int dfd, const char __user *name, unsigned flags,
		 struct path *path, int *empty)
{
	struct nameidata nd;
	struct filename *tmp = getname_flags(name, flags, empty);
	int err = PTR_ERR(tmp);
	if (!IS_ERR(tmp)) {

		BUG_ON(flags & LOOKUP_PARENT);

		err = filename_lookup(dfd, tmp, flags, &nd);
		putname(tmp);
		if (!err)
			*path = nd.path;
	}
	return err;
}

#define EMBEDDED_NAME_MAX	(PATH_MAX - sizeof(struct filename))

#define __getname()		kmem_cache_alloc(names_cachep, GFP_KERNEL)


struct filename *
getname_flags(const char __user *filename, int flags, int *empty)
{
	struct filename *result, *err;
	int len;
	long max;
	char *kname;

	result = audit_reusename(filename);


	result = __getname();
	result->refcnt = 1;

	/*
	 * First, try to embed the struct filename inside the names_cache
	 * allocation
	 */
	/*开头嵌入一个struct filename*/
	kname = (char *)result + sizeof(*result);
	result->name = kname;
	result->separate = false;
	max = EMBEDDED_NAME_MAX;

recopy:
	len = strncpy_from_user(kname, filename, max);

	result->uptr = filename;
	result->aname = NULL;
	audit_getname(result);
	return result;

error:
	putname(result);
	return err;
}
/*flags = LOOKUP_FOLLOW*/
static int filename_lookup(int dfd, struct filename *name,
				unsigned int flags, struct nameidata *nd)
{
	/*flags添加LOOKUP_RCU*/
	int retval = path_lookupat(dfd, name->name, flags | LOOKUP_RCU, nd);
	if (unlikely(retval == -ECHILD))
		retval = path_lookupat(dfd, name->name, flags, nd);
	if (unlikely(retval == -ESTALE))
		retval = path_lookupat(dfd, name->name,
						flags | LOOKUP_REVAL, nd);

	if (likely(!retval))
		audit_inode(name, nd->path.dentry, flags & LOOKUP_PARENT);
	return retval;
}

/* Returns 0 and nd will be valid on success; Retuns error, otherwise. */
/*flags = LOOKUP_RCU | LOOKUP_FOLLOW*/
static int path_lookupat(int dfd, const char *name,
				unsigned int flags, struct nameidata *nd)
{
	struct path path;
	int err;

	/*
	 * Path walking is largely split up into 2 different synchronisation
	 * schemes, rcu-walk and ref-walk (explained in
	 * Documentation/filesystems/path-lookup.txt). These share much of the
	 * path walk code, but some things particularly setup, cleanup, and
	 * following mounts are sufficiently divergent that functions are
	 * duplicated. Typically there is a function foo(), and its RCU
	 * analogue, foo_rcu().
	 *
	 * -ECHILD is the error number of choice (just to avoid clashes) that
	 * is returned if some aspect of an rcu-walk fails. Such an error must
	 * be handled by restarting a traditional ref-walk (which will always
	 * be able to complete).
	 */
	err = path_init(dfd, name, flags, nd);
	if (!err && !(flags & LOOKUP_PARENT)) {
		err = lookup_last(nd, &path);
		while (err > 0) {
			void *cookie;
			struct path link = path;
			err = may_follow_link(&link, nd);
			if (unlikely(err))
				break;
			nd->flags |= LOOKUP_PARENT;
			err = follow_link(&link, nd, &cookie);
			if (err)
				break;
			err = lookup_last(nd, &path);
			put_link(nd, &link, cookie);
		}
	}

	if (!err)
		err = complete_walk(nd);

	if (!err && nd->flags & LOOKUP_DIRECTORY) {
		if (!d_can_lookup(nd->path.dentry)) {
			path_put(&nd->path);
			err = -ENOTDIR;
		}
	}

	path_cleanup(nd);
	return err;
}

/*flags = LOOKUP_RCU | LOOKUP_FOLLOW*/
static int path_init(int dfd, const char *name, unsigned int flags,
		     struct nameidata *nd)
{
	int retval = 0;

	nd->last_type = LAST_ROOT; /* if there are only slashes... */
	nd->flags = flags | LOOKUP_JUMPED | LOOKUP_PARENT;
	nd->depth = 0;
	nd->base = NULL;
	if (flags & LOOKUP_ROOT) {/*不走这个路径*/
		struct dentry *root = nd->root.dentry;
		struct inode *inode = root->d_inode;
		if (*name) {
			if (!d_can_lookup(root))
				return -ENOTDIR;
			retval = inode_permission(inode, MAY_EXEC);
			if (retval)
				return retval;
		}
		nd->path = nd->root;
		nd->inode = inode;
		if (flags & LOOKUP_RCU) {
			rcu_read_lock();
			nd->seq = __read_seqcount_begin(&nd->path.dentry->d_seq);
			nd->m_seq = read_seqbegin(&mount_lock);
		} else {
			path_get(&nd->path);
		}
		goto done;
	}

	nd->root.mnt = NULL;

	nd->m_seq = read_seqbegin(&mount_lock);
	if (*name=='/') {/*如果是从根目录开始，本次分析中是从根目录开始*/
		if (flags & LOOKUP_RCU) {/*执行该路径*/
			rcu_read_lock();
			/**
			 *1.获得当前进程的fs
			 *2.从fs中得到当前进程的root，并赋值给nd->root
			 *从而也就得到了根目录的dentry
			 */
			nd->seq = set_root_rcu(nd);
		} else {
			set_root(nd);
			path_get(&nd->root);
		}
		nd->path = nd->root;
	} else if (dfd == AT_FDCWD) {
		if (flags & LOOKUP_RCU) {
			struct fs_struct *fs = current->fs;
			unsigned seq;

			rcu_read_lock();

			do {
				seq = read_seqcount_begin(&fs->seq);
				nd->path = fs->pwd;
				nd->seq = __read_seqcount_begin(&nd->path.dentry->d_seq);
			} while (read_seqcount_retry(&fs->seq, seq));
		} else {
			get_fs_pwd(current->fs, &nd->path);
		}
	} else {
		/* Caller must check execute permissions on the starting path component */
		struct fd f = fdget_raw(dfd);
		struct dentry *dentry;

		if (!f.file)
			return -EBADF;

		dentry = f.file->f_path.dentry;

		if (*name) {
			if (!d_can_lookup(dentry)) {
				fdput(f);
				return -ENOTDIR;
			}
		}

		nd->path = f.file->f_path;
		if (flags & LOOKUP_RCU) {
			if (f.flags & FDPUT_FPUT)
				nd->base = f.file;
			nd->seq = __read_seqcount_begin(&nd->path.dentry->d_seq);
			rcu_read_lock();
		} else {
			path_get(&nd->path);
			fdput(f);
		}
	}

	/*当前进程根目录的inode*/
	nd->inode = nd->path.dentry->d_inode;
	if (!(flags & LOOKUP_RCU))
		goto done;
	if (likely(!read_seqcount_retry(&nd->path.dentry->d_seq, nd->seq)))
		goto done;
	if (!(nd->flags & LOOKUP_ROOT))
		nd->root.mnt = NULL;
	rcu_read_unlock();
	return -ECHILD;
done:
	current->total_link_count = 0;
	return link_path_walk(name, nd);
}

static __always_inline unsigned set_root_rcu(struct nameidata *nd)
{
	struct fs_struct *fs = current->fs;
	unsigned seq, res;

	do {
		seq = read_seqcount_begin(&fs->seq);
		nd->root = fs->root;
		res = __read_seqcount_begin(&nd->root.dentry->d_seq);
	} while (read_seqcount_retry(&fs->seq, seq));
	return res;
}

/*flags = LOOKUP_RCU | LOOKUP_FOLLOW | LOOKUP_JUMPED | LOOKUP_PARENT*/
static int link_path_walk(const char *name, struct nameidata *nd)
{
	struct path next;
	int err;
	
	while (*name=='/')
		name++;
	if (!*name)
		return 0;

	/* At this point we know we have a real path component. */
	for(;;) {
		u64 hash_len;
		int type;

		/*检查权限*/
		err = may_lookup(nd);
 		if (err)
			break;

		hash_len = hash_name(name);

		type = LAST_NORM;
		if (name[0] == '.') 
			switch (hashlen_len(hash_len)) {
			case 2:
				if (name[1] == '.') {
					type = LAST_DOTDOT;
					nd->flags |= LOOKUP_JUMPED;
				}
				break;
			case 1:
				type = LAST_DOT;
		}
		if (likely(type == LAST_NORM)) {
			struct dentry *parent = nd->path.dentry;
			nd->flags &= ~LOOKUP_JUMPED;
			if (unlikely(parent->d_flags & DCACHE_OP_HASH)) {
				struct qstr this = { { .hash_len = hash_len }, .name = name };
				err = parent->d_op->d_hash(parent, &this);
				if (err < 0)
					break;
				hash_len = this.hash_len;
				name = this.name;
			}
		}

		nd->last.hash_len = hash_len;
		nd->last.name = name;
		nd->last_type = type;

		name += hashlen_len(hash_len);
		if (!*name)
			return 0;
		/*
		 * If it wasn't NUL, we know it was '/'. Skip that
		 * slash, and continue until no more slashes.
		 */
		do {
			name++;
		} while (unlikely(*name == '/'));
		if (!*name)
			return 0;

		err = walk_component(nd, &next, LOOKUP_FOLLOW);
		if (err < 0)
			return err;

		if (err) {
			err = nested_symlink(&next, nd);
			if (err)
				return err;
		}
		if (!d_can_lookup(nd->path.dentry)) {
			err = -ENOTDIR; 
			break;
		}
	}
	terminate_walk(nd);
	return err;
}

static inline int walk_component(struct nameidata *nd, struct path *path,
		int follow)
{
	struct inode *inode;
	int err;
	/*
	 * "." and ".." are special - ".." especially so because it has
	 * to be able to know about the current root directory and
	 * parent relationships.
	 */
	if (unlikely(nd->last_type != LAST_NORM))
		return handle_dots(nd, nd->last_type);
	/*先快速查找，如果找不到在执行lookup_slow
	 *快速查找是在hash链表中查找，首次打开是没有加入到dentry_hashtable
	 *链表中的
	 */
	err = lookup_fast(nd, path, &inode);
	if (unlikely(err)) {
		if (err < 0)
			goto out_err;

		err = lookup_slow(nd, path);
		if (err < 0)
			goto out_err;

		inode = path->dentry->d_inode;
	}
	err = -ENOENT;
	if (!inode || d_is_negative(path->dentry))
		goto out_path_put;

	if (should_follow_link(path->dentry, follow)) {
		if (nd->flags & LOOKUP_RCU) {
			if (unlikely(unlazy_walk(nd, path->dentry))) {
				err = -ECHILD;
				goto out_err;
			}
		}
		BUG_ON(inode != path->dentry->d_inode);
		return 1;
	}
	path_to_nameidata(path, nd);
	nd->inode = inode;
	return 0;

out_path_put:
	path_to_nameidata(path, nd);
out_err:
	terminate_walk(nd);
	return err;
}

