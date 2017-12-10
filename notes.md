#### dentry

对于/user/bin/vim

/只是用来进行路径区分的，不会有dentry，除了根目录"/",根目录对应一个dentry,它的名称就是"/"

对上面的路径，对应的dentry为/,user,bin,vim

debugfs文件系统会被挂载到/sys/kernel/debug/,再从之前sys文件系统已经被挂在到/sys。所以sys 是一个挂载点，在dentry_hashtable中也会有缓存

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

