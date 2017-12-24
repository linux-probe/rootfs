#### dentry

对于/user/bin/vim

/只是用来进行路径区分的，不会有dentry，除了根目录"/",根目录对应一个dentry,它的名称就是"/"

对上面的路径，对应的dentry为/,user,bin,vim

debugfs文件系统会被挂载到/sys/kernel/debug/,再从之前sys文件系统已经被挂在到/sys。所以sys 是一个挂载点，在dentry_hashtable中也会有缓存。

d_rehash(dentry);会把dentry添加到dentry_hashtable缓存中。

#### struct mount

```c
struct mount {
	struct hlist_node mnt_hash;
	struct mount *mnt_parent;/*该挂载点对应的父挂载点*/
	struct dentry *mnt_mountpoint;/*该挂载点对应的entry(上一个系统的)*/
	struct vfsmount mnt;
  ｝
```

struct mount *mnt_parent;表示该挂载信息的父对应信息。如/sys此时已经挂载了sys文件系统，则sys对应的mount的父mount应为/的mount。

struct dentry *mnt_mountpoint; 表示挂载点对的dentry，如/sys，则sys对应的mnt_mountpoint的名称为sys

#### struct vfsmount

```c
struct vfsmount {
	struct dentry *mnt_root;	/* root of the mounted tree*/
	struct super_block *mnt_sb;	/* pointer to superblock */
	int mnt_flags;
};
```
表示挂载的文件系统的root dentry该dentry的名称为"/"

所以所有的struct vfsmount中的mnt_root对应的名称都为“/”,但是**可以通过struct vfsmount mnt很容易得到struct mount，从而可以对挂载点的信息进行读取** 。struct mount内嵌了一个struct vfsmount mnt

#### struct path

```
struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

```

在path中dentry最终指向需要寻找的文件的dentry，而mnt间接的指向该文件所在文件系统的挂载信息struct mount，进而得到挂载点等信息。

#### debugfs挂载过程

在debugfs还没有在用户空间执行mount命令进行挂载的时候，在内核初始化的时候，就有很多驱动程序要用了，需要怎么处理了，下面是regulator_init中的例子（在分析的系统中，是第一个使用degbugfs系统的）

##### regulator_init

```c
static int __init regulator_init(void)
{
	ret = class_register(&regulator_class);
	debugfs_root = debugfs_create_dir("regulator", NULL);
	debugfs_create_file("supply_map", 0444, debugfs_root, NULL,
			    &supply_map_fops);
	......
}
```
##### debugfs_create_dir
```c
struct dentry *debugfs_create_dir(const char *name, struct dentry *parent)
{
	struct dentry *dentry = start_creating(name, parent);
	struct inode *inode;
	inode = debugfs_get_inode(dentry->d_sb);
	inode->i_mode = S_IFDIR | S_IRWXU | S_IRUGO | S_IXUGO;
	inode->i_op = &simple_dir_inode_operations;
	inode->i_fop = &simple_dir_operations;

	/* directory inodes start off with i_nlink == 2 (for "." entry) */
	inc_nlink(inode);
	d_instantiate(dentry, inode);
	inc_nlink(dentry->d_parent->d_inode);
	fsnotify_mkdir(dentry->d_parent->d_inode, dentry);
	return end_creating(dentry);
}
```
##### start_creating
```c
static struct dentry *start_creating(const char *name, struct dentry *parent)
{
	struct dentry *dentry;
	int error;
	error = simple_pin_fs(&debug_fs_type, &debugfs_mount, &debugfs_mount_count);
	if (!parent)
		parent = debugfs_mount->mnt_root;
	mutex_lock(&parent->d_inode->i_mutex);
	dentry = lookup_one_len(name, parent, strlen(name));
	return dentry;
}
```

##### simple_pin_fs

```c
int simple_pin_fs(struct file_system_type *type, struct vfsmount **mount, int *count)
{
	struct vfsmount *mnt = NULL;
	mnt = vfs_kern_mount(type, MS_KERNMOUNT, type->name, NULL);
	*mount = mnt;
}
```

simple_pin_fs会调用vfs_kern_mount，但是于从user空间调用mount命令不同，kernel调用时flags参数为

**MS_KERNMOUNT** 。

调用vfs_kern_mount之后，就已经分配了根super_block，并且会执行hlist_add_head(&s->s_instances, &type->fs_supers);将super_block的s_instances加入filesystem_type的哈希链表fs_supers中。后面在挂载的时候，检查已经存在就不用在分配。

#### devtmpfs

在kernel启动的过程中，kernel挂载了devtmpfs,但是在执行mount命令的时候看不到有该文件系统信息。

```c
int __init devtmpfs_init(void)
{
	int err = register_filesystem(&dev_fs_type);

	thread = kthread_run(devtmpfsd, &err, "kdevtmpfs");
	if (!IS_ERR(thread)) {
		wait_for_completion(&setup_done);
	} else {
	}

	printk(KERN_INFO "devtmpfs: initialized\n");
	return 0;
}
```

```c
static int devtmpfsd(void *p)
{
	char options[] = "mode=0755";
	int *err = p;
	*err = sys_unshare(CLONE_NEWNS);
	*err = sys_mount("devtmpfs", "/", "devtmpfs", MS_SILENT, options);
	sys_chdir("/.."); /* will traverse into overmounted root */
	sys_chroot(".");
	complete(&setup_done);
	return 0;
}
```

kernel起了一个名为kdevtmpfs的内核线程执行操作，线程的执行函数为devtmpfsd。在该函数中调用sys_mount进行挂载。**但是在挂载之前执行了一个sys_unshare(CLONE_NEWNS);该函数表示新的进程在一个新的命名空间中（namespace）。而mount命令查看的是当前进程的命名空间的挂载信息，所以看不到devtmpfs的挂载信息**。