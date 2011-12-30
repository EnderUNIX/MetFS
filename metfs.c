/*
 * Metin KAYA <metin@EnderUNIX.org>
 *
 * April 2008, Istanbul/TURKIYE
 * http://www.enderunix.org/metfs/
 *
 * $Id: metfs.c,v 1.16 2008/04/13 07:55:33 mk Exp $
 */

#define  FUSE_USE_VERSION 26
#define  _GNU_SOURCE

#include "config.h"
#include "mstring.h"
#include "readpassphrase.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <gcrypt.h>
#include <libtar.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ulockmgr.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#define  ARCFOUR_KEY_LEN       16  /* Maximum key length of ARCFOUR cipher algorithm                     */
#define  BUFSIZE             1024 
#define  MAX_KEY_LEN          256  /* maximum length of the user key                                     */
#define  MIN_KEY_LEN            6  /* minimum length of the user key                                     */
#define  SEC_MEM_SIZE       32768  /* the size of secure memory in bytes (32 KB)                         */

char     key[ARCFOUR_KEY_LEN];

static void
metfs_error(const char *format, ...)
{
	va_list arg_ptr;

	va_start(arg_ptr, format);
	vfprintf(stderr, format, arg_ptr);
	va_end(arg_ptr);

	exit(-1);
}

static unsigned char *
metfs_md5(const char *data, int len)
{
        gcry_md_hd_t hd;

        if (gcry_md_open(&hd, GCRY_MD_MD5, GCRY_MD_FLAG_SECURE))
                metfs_error("MD5 grcy_md_open() failed\n");

        if (gcry_md_get_algo_dlen(GCRY_MD_MD5) > ARCFOUR_KEY_LEN)
                metfs_error("MD5 grcy_md_get_algo_dlen() failed: %d\n", gcry_md_get_algo_dlen(GCRY_MD_MD5));

        gcry_md_write(hd, data, len);

        return (gcry_md_read(hd, GCRY_MD_MD5));
}

static void
metfs_decrypt(int algo_num, int mode, char *out, char *plain, char *dec_key, int len)
{
	gcry_cipher_hd_t  hd;
	gcry_error_t      err = 0;
	int               keylen;

	keylen = gcry_cipher_get_algo_keylen(algo_num);
	if (!keylen)
		metfs_error("algorithm %d, mode %d, gcry_cipher_get_algo_keylen() died\n", algo_num, mode);

	if (keylen < MIN_KEY_LEN || keylen > 32)
		metfs_error("algorithm %d, mode %d, keylength problem (%d)\n", algo_num, mode, keylen);

	err = gcry_cipher_open(&hd, algo_num, mode, GCRY_CIPHER_SECURE);
	if (err)
		metfs_error("algorithm %d, mode %d, grcy_open_cipher() died: %s\n", algo_num, mode, gpg_strerror(err));

	err = gcry_cipher_setkey(hd, dec_key, keylen);
	if (err) {
		gcry_cipher_close(hd);
		metfs_error("algorithm %d, mode %d, gcry_cipher_setkey() died: %s\n", algo_num, mode, gpg_strerror(err));
	}

	err = gcry_cipher_decrypt(hd, plain, len, out, len);
	if (err) {
		gcry_cipher_close(hd);
		metfs_error("algorithm %d, mode %d, gcry_cipher_decrypt() died: %s\n", algo_num, mode, gpg_strerror(err));
	}

	gcry_cipher_close(hd);
}

static void
metfs_encrypt(int algo_num, int mode, char *plain, char *out, char *enc_key, int len)
{
	gcry_cipher_hd_t  hd;
	gcry_error_t      err = 0;
	int               keylen;

	keylen = gcry_cipher_get_algo_keylen(algo_num);
	if (!keylen)
		metfs_error("algorithm %d, mode %d, gcry_cipher_get_algo_keylen() died\n", algo_num, mode);

	if (keylen < MIN_KEY_LEN || keylen > 32)
		metfs_error("algorithm %d, mode %d, keylength problem (%d)\n", algo_num, mode, keylen);

	err = gcry_cipher_open(&hd, algo_num, mode, GCRY_CIPHER_SECURE);
	if (err)
		metfs_error("algorithm %d, mode %d, grcy_open_cipher() died: %s\n", algo_num, mode, gpg_strerror(err));

	err = gcry_cipher_setkey(hd, enc_key, keylen);
	if (err) {
		gcry_cipher_close(hd);
		metfs_error("algorithm %d, mode %d, gcry_cipher_setkey() died: %s\n", algo_num, mode, gpg_strerror(err));
	}

	err = gcry_cipher_encrypt(hd, out, len, plain, len);
	if (err) {
		gcry_cipher_close(hd);
		metfs_error("algorithm %d, mode %d, gcry_cipher_encrypt() died: %s\n", algo_num, mode, gpg_strerror(err));
	}

	gcry_cipher_close(hd);
}

static int
metfs_getattr(const char *path, struct stat *stbuf)
{

	if (lstat(path, stbuf) == -1)
		return (-errno);

	return (0);
}

static int
metfs_fgetattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi)
{

	(void) path;
	if (fstat(fi->fh, stbuf) == -1)
		return (-errno);

	return (0);
}

static int
metfs_access(const char *path, int mask)
{

	if (access(path, mask) == -1)
		return (-errno);

	return (0);
}

static int
metfs_readlink(const char *path, char *buf, size_t size)
{
	int res;

	if ((res = readlink(path, buf, size - 1)) == -1)
		return (-errno);

	buf[res] = '\0';

	return (0);
}

struct metfs_dirp {
	DIR            *dp;
	struct dirent  *entry;
	off_t          offset;
};

static int
metfs_opendir(const char *path, struct fuse_file_info *fi)
{
	struct metfs_dirp *d = NULL;

	if ((d = malloc(sizeof(struct metfs_dirp))) == NULL)
		return (-ENOMEM);

	if ((d->dp = opendir(path)) == NULL) {
		free(d);
		return (-errno);
	}
	d->offset = 0;
	d->entry  = NULL;
	fi->fh    = (unsigned long) d;

	return (0);
}

static struct metfs_dirp *
get_dirp(struct fuse_file_info *fi)
{
	return ((struct metfs_dirp *) (uintptr_t) fi->fh);
}

static int
metfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
	struct metfs_dirp *d = NULL;

	d = get_dirp(fi);
	(void) path;
	if (offset != d->offset) {
		seekdir(d->dp, offset);
		d->entry  = NULL;
		d->offset = offset;
	}

	for (;;) {
		struct stat st;
		off_t  nextoff;

		if (!d->entry) {
			d->entry = readdir(d->dp);
			if (!d->entry)
				break;
		}

		memset(&st, 0x0, sizeof(st));
		st.st_ino  = d->entry->d_ino;
		st.st_mode = d->entry->d_type << 12;
		nextoff    = telldir(d->dp);
		if (filler(buf, d->entry->d_name, &st, nextoff))
			break;

		d->entry = NULL;
		d->offset = nextoff;
	}

	return (0);
}

static int
metfs_releasedir(const char *path, struct fuse_file_info *fi)
{
	struct metfs_dirp *d = NULL;

	d = get_dirp(fi);
	(void) path;
	closedir(d->dp);
	free(d);

	return (0);
}

static int
metfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

	if (S_ISFIFO(mode))
		res = mkfifo(path, mode);
	else
		res = mknod(path, mode, rdev);

	if (res == -1)
		return (-errno);

	return (0);
}

static int
metfs_mkdir(const char *path, mode_t mode)
{

	if (mkdir(path, mode) == -1)
		return (-errno);

	return (0);
}

static int
metfs_unlink(const char *path)
{

	if (unlink(path) == -1)
		return (-errno);

	return (0);
}

static int
metfs_rmdir(const char *path)
{

	if (rmdir(path) == -1)
		return (-errno);

	return (0);
}

static int
metfs_symlink(const char *from, const char *to)
{

	if (symlink(from, to) == -1)
		return (-errno);

	return (0);
}

static int
metfs_rename(const char *from, const char *to)
{

	if (rename(from, to) == -1)
		return (-errno);

	return (0);
}

static int
metfs_link(const char *from, const char *to)
{

	if (link(from, to) == -1)
		return (-errno);

	return (0);
}

static int
metfs_chmod(const char *path, mode_t mode)
{

	if (chmod(path, mode) == -1)
		return (-errno);

	return (0);
}

static int
metfs_chown(const char *path, uid_t uid, gid_t gid)
{

	if (lchown(path, uid, gid) == -1)
		return (-errno);

	return (0);
}

static int
metfs_utimens(const char *path, const struct timespec ts[2])
{
	struct timeval tv[2];

	tv[0].tv_sec  = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec  = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	if (utimes(path, tv) == -1)
		return (-errno);

	return (0);
}

static int
metfs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int fd = 0;

	if ((fd = open(path, fi->flags, mode)) == -1)
		return (-errno);

	fi->fh = fd;

	return (0);
}

static int
metfs_open(const char *path, struct fuse_file_info *fi)
{
	int fd = 0;

	if ((fd = open(path, fi->flags)) == -1)
		return (-errno);

	fi->fh = fd;

	return (0);
}

static int
metfs_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	int     res = 0;
	char    decrypted[4096];
	char    encrypted[4096];
	(void)  path;

	memset(decrypted, 0x0, 4096);
	memset(encrypted, 0x0, 4096);

	if ((res = pread(fi->fh, encrypted, 4096, offset)) == -1)
		return (-errno);

	metfs_decrypt(GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM, encrypted, decrypted, key, res);
	memcpy(buf, decrypted, res);

        return (res);
}

static int
metfs_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	int  res = 0, fd = 0, full_blk = 0, remainder = 0, total_wr = 0;
	char *plain     = NULL;
	char *encrypted = NULL;

	if (offset % 4096 == 0) {
        plain = calloc(size, sizeof(char));
		if (!plain)
			return (-ENOMEM);

		encrypted = calloc(size, sizeof(char));
		if (!encrypted) {
			free(plain);
			return (-ENOMEM);
		}

		memcpy(plain, buf, size);
       	metfs_encrypt(GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM, plain, encrypted, key, size);
		if ((res = pwrite(fi->fh, encrypted, size, offset)) == -1)
	    	res = (-errno);
	} else {
		full_blk  = offset / 4096;
		remainder = offset % 4096;
		total_wr  = remainder + size;

	    plain = (char *) calloc(total_wr, sizeof(char));
		if (!plain)
			return (-ENOMEM);

		encrypted = calloc(total_wr, sizeof(char));
		if (!encrypted) {
			free(plain);
			return (-ENOMEM);
		}

		if ((fd = open(path, O_RDWR)) == -1)
			return (-errno);

		if ((res = pread(fd, encrypted, remainder, full_blk * 4096)) != remainder) {
       		free(plain);
			free(encrypted);
			close(fd);
			return (-errno);
		}

		metfs_decrypt(GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM, encrypted, plain, key, res);
		memcpy(plain + res, buf, size);
		memset(encrypted, 0x0, total_wr);
       		metfs_encrypt(GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM, plain, encrypted, key, total_wr);
		if ((res = pwrite(fd, encrypted, total_wr, full_blk * 4096)) == -1) {
       		free(plain);
			free(encrypted);
			close(fd);
			return (-errno);
		}

		close(fd);
		res = size;
	}

    free(plain);
	free(encrypted);	

	return (res);
}

static int
metfs_truncate(const char *path, off_t size)
{

	if (truncate(path, size) == -1)
		return (-errno);

	return (0);
}

static int
metfs_ftruncate(const char *path, off_t size, struct fuse_file_info *fi)
{

	(void) path;
	if (ftruncate(fi->fh, size) == -1)
		return (-errno);

	return (0);
}

static int
metfs_statfs(const char *path, struct statvfs *stbuf)
{

	if (statvfs(path, stbuf) == -1)
		return (-errno);

	return (0);
}

static int
metfs_flush(const char *path, struct fuse_file_info *fi)
{

	(void) path;
	if (close(dup(fi->fh)) == -1)
		return (-errno);

	return (0);
}

static int
metfs_release(const char *path, struct fuse_file_info *fi)
{

	(void) path;
	close(fi->fh);

	return (0);
}

static int
metfs_fsync(const char *path, int isdatasync, struct fuse_file_info *fi)
{
	int res;

	(void) path;
#ifndef HAVE_FDATASYNC
	(void) isdatasync;
#else
	if (isdatasync)
		res = fdatasync(fi->fh);
	else
#endif
		res = fsync(fi->fh);
	if (res == -1)
		return (-errno);

	return (0);
}

#ifdef HAVE_SETXATTR
static int
metfs_setxattr(const char *path, const char *name, const char *value, size_t size, int flags)
{

	if (lsetxattr(path, name, value, size, flags) == -1)
		return (-errno);

		return (0);
}

static int
metfs_getxattr(const char *path, const char *name, char *value, size_t size)
{
	int res;

	if ((res = lgetxattr(path, name, value, size)) == -1)
		return (-errno);

	return (res);
}

static int
metfs_listxattr(const char *path, char *list, size_t size)
{
	int res;

	if ((res = llistxattr(path, list, size)) == -1)
		return (-errno);

	return (res);
}

static int
metfs_removexattr(const char *path, const char *name)
{

	if (lremovexattr(path, name) == -1)
		return (-errno);

	return (0);
}
#endif /* HAVE_SETXATTR */

static int
metfs_lock(const char *path, struct fuse_file_info *fi, int cmd, struct flock *lock)
{

	(void) path;

	return (ulockmgr_op(fi->fh, cmd, lock, &fi->lock_owner, sizeof(fi->lock_owner)));
}

static struct fuse_operations metfs_oper = {
	.getattr	= metfs_getattr,
	.fgetattr	= metfs_fgetattr,
	.access		= metfs_access,
	.readlink	= metfs_readlink,
	.opendir	= metfs_opendir,
	.readdir	= metfs_readdir,
	.releasedir	= metfs_releasedir,
	.mknod		= metfs_mknod,
	.mkdir		= metfs_mkdir,
	.symlink	= metfs_symlink,
	.unlink		= metfs_unlink,
	.rmdir		= metfs_rmdir,
	.rename		= metfs_rename,
	.link		= metfs_link,
	.chmod		= metfs_chmod,
	.chown		= metfs_chown,
	.truncate	= metfs_truncate,
	.ftruncate	= metfs_ftruncate,
	.utimens	= metfs_utimens,
	.create		= metfs_create,
	.open		= metfs_open,
	.read		= metfs_read,
	.write		= metfs_write,
	.statfs		= metfs_statfs,
	.flush		= metfs_flush,
	.release	= metfs_release,
	.fsync		= metfs_fsync,
#ifdef HAVE_SETXATTR
	.setxattr       = metfs_setxattr,
	.getxattr       = metfs_getxattr,
	.listxattr      = metfs_listxattr,
	.removexattr    = metfs_removexattr,
#endif
	.lock		= metfs_lock,
};

GCRY_THREAD_OPTION_PTHREAD_IMPL;

static void
metfs_init_encryption(void)
{

	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
	gcry_control(GCRYCTL_INIT_SECMEM, SEC_MEM_SIZE, 0);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

static void
metfs_set_key(void)
{
	char *res1 = NULL;
	char *res2 = NULL;
	char pass_buf[MAX_KEY_LEN];
	char pass_buf2[MAX_KEY_LEN];

	memset(key, 0x0, ARCFOUR_KEY_LEN);

	for (;;) {
		memset(pass_buf,  0x0, MAX_KEY_LEN);
		memset(pass_buf2, 0x0, MAX_KEY_LEN);

		res1 = readpassphrase("New    MetFS Password: ", pass_buf, sizeof(pass_buf) - 1, RPP_ECHO_OFF);
		if (mstrlen(pass_buf) < MIN_KEY_LEN) {
			printf("Password cannot be shorter than %d characters, please try again.\n", MIN_KEY_LEN);
			continue;
		}

		res2 = readpassphrase("Verify MetFS Password: ", pass_buf2, sizeof(pass_buf2) - 1, RPP_ECHO_OFF);

		if (res1 && res2 && !strncmp(pass_buf, pass_buf2, MAX_KEY_LEN)) {
			memcpy(key, (char *) metfs_md5(pass_buf, mstrlen(pass_buf)), ARCFOUR_KEY_LEN);
		        break;
		} else {
			printf("Passwords did not match, please try again.\n");
		}
	}
}

static void
check_dir(const char *dir_name)
{
	DIR           *dp   = NULL;
	struct dirent *dirp = NULL;

	if ((dp = opendir(dir_name)) == NULL)
		   metfs_error("File: %s - Line: %d: %s.\n", __FILE__, __LINE__, strerror(errno));

	while ((dirp = readdir(dp)) != NULL)
                if (!strcmp(dirp->d_name, ".") || !strcmp(dirp->d_name, ".."))
			continue;
		else
			metfs_error("Working directory or mountpoint must be empty!\n");

	if (closedir(dp) == -1)
		metfs_error("File: %s - Line: %d : %s\n", __FILE__, __LINE__, strerror(errno));
}

static int
metfs_clean_workdir(const char *dirpath, const char *dir_name)
{
	char   new_path[1024];
	DIR    *dirp = NULL;
	struct dirent *direntp = NULL;
	struct stat st;

	memset(&st, 0x0, sizeof(st));

	if ((dirp = opendir(dirpath)) == NULL)
		metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));

	while ((direntp = readdir(dirp)) != NULL) {
		memset(new_path, 0x0, sizeof(new_path));

		if (strcmp(direntp->d_name, ".") !=0 && strcmp(direntp->d_name, "..") != 0) {
			snprintf(new_path, sizeof(new_path) - 1, "%s/%s", dirpath, direntp->d_name);
			if (lstat(new_path, &st) == -1) {
				closedir(dirp);
				metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));
                        }

			if (S_ISDIR(st.st_mode))
				metfs_clean_workdir(new_path, dir_name);
			else
				if (unlink(new_path) == -1)
					metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));
		}
	}
	if (closedir(dirp) == -1)
		metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));

	if (strcmp(dirpath, dir_name))
		if (rmdir(dirpath) == -1)
			metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));

        return (0);
}

static int
metfs_create_file(char *tarfile, char *dest, const char *passwd)
{
	char plain[BUFSIZE];
	char encrypted[BUFSIZE];
	FILE *fp = NULL;
	TAR  *t  = NULL;

	unlink(tarfile); /* remove old metfs file, if exist. */

	if (tar_open(&t, tarfile, NULL, O_WRONLY | O_CREAT, 0644, 0) == -1)
		metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));

	if (tar_append_tree(t, dest, "/") != 0) {
		tar_close(t);
		metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));
	}

	if (tar_append_eof(t) != 0) {
		tar_close(t);
		metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));
	}

	if (tar_close(t) != 0)
		metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));

	if ((fp = fopen(tarfile, "r+")) == NULL)
		metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));

	fseek(fp, 0L, SEEK_END);
	if (write(fileno(fp), passwd, ARCFOUR_KEY_LEN) != ARCFOUR_KEY_LEN)
		metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));

	memset(plain,     0x0, BUFSIZE);
	memset(encrypted, 0x0, BUFSIZE);

	if (pread(fileno(fp), plain, BUFSIZE - 1, 0) == -1)
		metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));

	metfs_encrypt(GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM, plain, encrypted, key, BUFSIZE - 1);

	if (pwrite(fileno(fp), encrypted, BUFSIZE - 1, 0) == -1)
		metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));

	if (fclose(fp) == -1)
		metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));

	return (0);
}

static int
metfs_extract_file(char *tarfile, char *rootdir, int fd)
{
	TAR  *t = NULL;
	char decrypted[BUFSIZE];
	char encrypted[BUFSIZE];

	memset(decrypted, 0x0, BUFSIZE);
	memset(encrypted, 0x0, BUFSIZE);

	if (pread(fd, encrypted, BUFSIZE - 1, 0) == -1)
		metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));

	metfs_decrypt(GCRY_CIPHER_ARCFOUR, GCRY_CIPHER_MODE_STREAM, encrypted, decrypted, key, BUFSIZE - 1);

	if (pwrite(fd, decrypted, BUFSIZE - 1, 0) == -1)
		metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));

	if (tar_open(&t, tarfile, NULL, O_RDONLY, 0, 0) == -1)
		metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));

	if (tar_extract_all(t, rootdir) != 0)
		metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));

	if (tar_close(t) != 0)
		metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));

	return (0);
}

int
main(int argc, char** argv)
{
	if (argc != 3 && argc != 4)
		metfs_error("Wrong number of parameters!\n"
			    "Usage (sequence of arguments is mandatory): metfs <full path to mountpoint> [-d] <full path to work dir>\n");

	check_dir(argv[1]);
	check_dir(argv[argc - 1]);

	char    *metfs_argv[8], fname[1024], tmp[512], *addr = NULL, *pass_res = NULL, pass_buf[MAX_KEY_LEN];
	int     metfs_argc = 0, i = 0, flag = 0, fd = 0;
	off_t   fsize = 0, offset = 0;
	struct  stat st;

	memset(&st,      0x0, sizeof(st));
	memset(fname,    0x0, sizeof(fname));
	memset(tmp,      0x0, sizeof(tmp));
	memset(pass_buf, 0x0, sizeof(pass_buf));

	for (i = 0; i < 7; i++)
		metfs_argv[i] = NULL; /* libfuse expects null args. */

	for (i = 0; i < argc; i++)
		metfs_argv[i] = argv[i];

	snprintf(tmp, sizeof(tmp) - 1, "%s/", argv[argc - 1]);
	strcpy(metfs_argv[argc - 1], "-omodules=subdir,subdir=");
	strncat(metfs_argv[argc - 1], tmp, 486);
	metfs_argv[argc] = "-omax_read=4096";       /* set max_read size as 4K       */
	metfs_argc       = argc + 1;

	metfs_init_encryption();

	printf("Enter your metfs file name (if you don't have, just hit ENTER): ");
	fgets(fname, sizeof(fname) - 1, stdin);
	if (mstrlen(fname) > 1) {
		fname[mstrlen(fname) - 1] = '\0';
		flag = 1;
	}

	if (flag) {
		if (stat(fname, &st) == -1)
			metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));
		fsize = st.st_size;

		if ((fd = open(fname, O_RDWR)) == -1)
			metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));

		offset = 0x0 & ~(sysconf(_SC_PAGE_SIZE) - 1);
		if ((addr = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, offset)) == MAP_FAILED)
			metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));

		pass_res = readpassphrase("Enter MetFS Password: ", pass_buf, sizeof(pass_buf) - 1, RPP_ECHO_OFF);
		if (!(pass_res && !memcmp(addr + fsize - ARCFOUR_KEY_LEN, (char *) metfs_md5(pass_buf, mstrlen(pass_buf)), ARCFOUR_KEY_LEN)))
			metfs_error("Wrong password!\n");

		write(STDOUT_FILENO, "Password OK...\n", 15);
		munmap(addr, fsize);
		memset(key, 0x0, ARCFOUR_KEY_LEN);
		memcpy(key, (char *) metfs_md5(pass_buf, mstrlen(pass_buf)), ARCFOUR_KEY_LEN);

		if (truncate(fname, fsize - ARCFOUR_KEY_LEN) == -1)
			metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));

		metfs_extract_file(fname, tmp, fd);

		if (pwrite(fd, key, ARCFOUR_KEY_LEN, fsize) != ARCFOUR_KEY_LEN)
			metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));

		if (close(fd) == -1)
			metfs_error("File: %s - Line: %d: %s\n", __FILE__, __LINE__, strerror(errno));
	} else {
		metfs_set_key();
		printf("Enter the file name that will contain your encrypted data [max. 1024 characters]: ");
		scanf("%s", fname);
	}

	umask(0);
	fuse_main(metfs_argc, metfs_argv, &metfs_oper, NULL);
	metfs_create_file(fname, tmp, key);
	metfs_clean_workdir(tmp, tmp);

	exit(0); /* game over... */
}
