#ifndef URINGXX_URINGXX_HPP
#define URINGXX_URINGXX_HPP

#include <cstdint>
#include <functional>
#include <memory>
#include <stdexcept>
#include <system_error>
#include <type_traits>
#include <utility>

#include <liburing.h>

namespace uring {

class uring;

template <typename F>
struct is_completion : std::bool_constant<std::is_invocable_v<F, uring &, std::int32_t> || std::is_invocable_v<F, uring &, io_uring_cqe &>> {
};

template <typename F>
static constexpr bool is_completion_v = is_completion<F>::value;

#ifdef __cpp_concepts
template <typename F>
concept completion = is_completion_v<F>;
#endif

//+ helper macros

#define ENABLE_IF(R, expr) std::enable_if_t<(expr), R>

#ifdef __cpp_concepts
#define ENABLE_IF_COMPLETION(R, T) \
    requires completion<T>         \
    return R
#else
#define ENABLE_IF_COMPLETION(R, T) ENABLE_IF(R, is_completion_v<T>)
#endif

//-

class uring {
public:
    using native_handle_type = int;
    static constexpr native_handle_type invalid_handle = -1;

    struct operation {
        friend uring;

    private:
        explicit constexpr operation(std::uint64_t v) noexcept
            : value { v }
        {
        }

        std::uint64_t value;
    };

    uring()
        : uring(UINT32_MAX)
    {
    }

    explicit uring(std::uint32_t entries)
        : uring(entries, IORING_SETUP_CLAMP)
    {
    }

    explicit uring(std::uint32_t entries, unsigned flags)
        : uring(entries, ([flags]() { io_uring_params params{}; params.flags = flags; return params; })())
    {
    }

private:
    explicit uring(std::uint32_t entries, io_uring_params &&params)
        : uring(entries, params)
    {
    }

public:
    explicit uring(std::uint32_t entries, io_uring_params &params)
        : m_uring(([&]() {
            io_uring ring;
            int result = io_uring_queue_init_params(entries, &ring, &params);
            if (result < 0)
                throw std::system_error(-result, std::system_category());
            return ring;
        })())
    {
    }

    uring(uring const &other) = delete;
    uring(uring &&other) = delete;

    uring &operator=(uring const &other) = delete;
    uring &operator=(uring &&other) = delete;

    [[nodiscard]] native_handle_type native_handle() noexcept
    {
        return m_uring.ring_fd;
    }

    template <typename F>
    ENABLE_IF(void, std::is_invocable_v<F>)
    post(F &&f)
    {
        async_noop([f = std::move(f)](uring &, std::uint32_t) mutable {
            (void)std::invoke(f);
        });
    }

    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_noop(F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_nop(&op);

        return submit(op, std::forward<F>(f));
    }

    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_readv(int fd, iovec const *iov, std::size_t len, off64_t offset, int flags, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_readv2(&op, fd, iov, len, offset, flags);

        return submit(op, std::forward<F>(f));
    }

    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_writev(int fd, iovec const *iov, std::size_t len, off64_t offset, int flags, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_writev2(&op, fd, iov, len, offset, flags);

        return submit(op, std::forward<F>(f));
    }

    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_fsync(int fd, int flags, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_fsync(&op, fd, flags);

        return submit(op, std::forward<F>(f));
    }

    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_poll_add(int fd, std::uint32_t events, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_poll_add(&op, fd, events);

        return submit(op, std::forward<F>(f));
    }

    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_poll_multishot(int fd, std::uint32_t events, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_poll_multishot(&op, fd, events);

        return submit(op, std::forward<F>(f));
    }

    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_poll_remove(operation operation, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_poll_remove(&op, operation.value);
        return submit(op, std::forward<F>(f));
    }

    /**
     * @brief Asynchronously adds, updates, or removes entries in the interest list of an epoll instance
     * @see [_man 2 epoll_ctl_](https://man.archlinux.org/man/epoll_ctl.2.en)
     * @see [_man 7 epoll_](https://man.archlinux.org/man/epoll.7.en)

     * @param epoll_fd file descriptor of the epoll instance
     * @param op operation to be performed, must be one of the folling constants:
     * - <b>EPOLL_CTL_ADD</b>: add an entry to the interest list of the epoll file descriptor,
     * - <b>EPOLL_CTL_MOD</b>: update the settings associated with `fd` in the interest list to the new settings specified in `event`.
     * - <b>EPOLL_CTL_DEL</b>: remove the target file descriptor fd from the interest list. The `event` argument is ignored and can be <b>`NULL`</b>.
     * @param fd file descriptor to perform the operations on
     * @param event events to listen to
     * @param f callback
     * @return id of the operation
     */
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_epoll_ctl(int epoll_fd, int op, int fd, epoll_event const *event, F &&f)
    {
        io_uring_sqe operation {};
        io_uring_prep_epoll_ctl(&operation, epoll_fd, fd, op, const_cast<epoll_event *>(event));

        return submit(op, std::forward<F>(f));
    }

    /**
     * @brief Synchronize a file segment's in-core state with it's underlying storage device
     * @see [_man 2 sync_file_range_](https://man.archlinux.org/man/sync_file_range.2.en)

     * @warning
     * <b>This operation is extremely dangerous.</b>
     * <b>None of these operations writes out the file's metadata.</b>
     * <b>There are no guarantees that the data will be available after a crash.</b>

     * @attention unlike the `sync_file_range` syscall, which uses `off_t` as the `nbytes`
     * argument (which might be a signed 64bit integer), io_uring uses an unsigned 32bit integer.

     * @param fd file descriptor
     * @param offset offset into the file
     * @param nbytes number of bytes to sync
     * @param flags see [_man 2 sync_file_range_](https://man.archlinux.org/man/sync_file_range.2.en#Some_details)
     * @param f callback
     * @return id of the operation
     */
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_sync_file_range(int fd, off64_t offset, std::uint32_t nbytes, unsigned int flags, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_sync_file_range(&op, fd, nbytes, offset, flags);

        return submit(op, std::forward<F>(f));
    }

    /**
     * @brief Transmit a message to another socket.
     * @see [_man 2 sendmsg](https://man.archlinux.org/man/sendmsg.2.en)

     * @param fd file descriptor
     * @param msg message to transmit
     * @param flags see [_man 2 sendmsg_](https://man.archlinux.org/man/sendmsg.2.en#The_flags_argument)
     * @param f callback
     */
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_sendmsg(int fd, msghdr const *msg, int flags, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_sendmsg(&op, fd, msg, flags);

        return submit(op, std::forward<F>(f));
    }

    // recvmsg(2)
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_recvmsg(int fd, msghdr *msg, int flags, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_recvmsg(&op, fd, msg, flags);

        return submit(op, std::forward<F>(f));
    }

    // send(2)
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_send(int fd, void const *buf, std::size_t len, int flags, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_send(&op, fd, buf, len, flags);

        return submit(op, std::forward<F>(f));
    }

    // recv(2)
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_recv(int fd, void *buf, std::size_t len, int flags, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_recv(&op, fd, buf, len, flags);

        return submit(op, std::forward<F>(f));
    }

    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_timeout(__kernel_timespec const *timeout, std::uint32_t count, int flags, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_timeout(&op, const_cast<__kernel_timespec *>(timeout), count, flags);

        return submit(op, std::forward<F>(f));
    }

    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_timeout_remove(std::uint64_t timer_id, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_timeout_remove(&op, timer_id, 0);

        return submit(op, std::forward<F>(f));
    }

    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_timeout_update(std::uint64_t timer_id, __kernel_timespec const *timeout, bool absolute, F &&f)
    {
        io_uring_sqe op {};
        // this wil cast timer_id to a pointer which might not be 64bits
        io_uring_prep_timeout_update(&op, const_cast<__kernel_timespec *>(timeout), timer_id, IORING_TIMEOUT_ABS * absolute);
        op.addr = timer_id; // set timer_id directly

        return submit(op, std::forward<F>(f));
    }

    // accept4(2)
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_accept(int fd, sockaddr *addr, socklen_t *addrlen, int flags, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_accept(&op, fd, addr, addrlen, flags);

        return submit(op, std::forward<F>(f));
    }

    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_cancel(std::uint64_t operation, F &&f)
    {
        io_uring_sqe op {};
        // this wil cast operation to a pointer which might not be 64bits
        io_uring_prep_cancel(&op, nullptr, 0);
        op.addr = operation; // set operation directly

        return submit(op, std::forward<F>(f));
    }

    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_link_timeout(__kernel_timespec const *timeout, bool absolute, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_link_timeout(&op, const_cast<__kernel_timespec *>(timeout), IORING_TIMEOUT_ABS * absolute);

        return submit(op, std::forward<F>(f));
    }

    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_connect(int fd, sockaddr const *addr, socklen_t len, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_connect(&op, fd, addr, len);

        return submit(op, std::forward<F>(f));
    }

    // fallocate(2)
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_fallocate(int fd, int mode, off_t offset, off_t len, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_fallocate(&op, fd, mode, offset, len);

        return submit(op, std::forward<F>(f));
    }

    // posix_fadvise(2)
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_fadvice(int fd, off_t offset, off_t len, int advice, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_fadvise(&op, fd, offset, len, advice);

        return submit(op, std::forward<F>(f));
    }

    // madvice(2)
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_madvice(void *addr, std::size_t length, int advice, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_madvise(&op, addr, length, advice);

        return submit(op, std::forward<F>(f));
    }

    // openat(2)
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_openat(int dir_fd, char const *pathname, int flags, mode_t mode, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_openat(&op, dir_fd, pathname, flags, mode);

        return submit(op, std::forward<F>(f));
    }

    // open(2)
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_open(char const *pathname, int flags, mode_t mode, F &&f)
    {
        return async_openat(AT_FDCWD, pathname, flags, mode, std::forward<F>(f));
    }

    // openat2(2)
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_openat2(int dir_fd, char const *pathname, ::open_how *how, std::size_t size, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_openat2(&op, dir_fd, pathname, how);
        op.len = size; // just to be safe

        return submit(op, std::forward<F>(f));
    }

    // close(2)
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_close(int fd, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_close(&op, fd);

        return submit(op, std::forward<F>(f));
    }

    // statx(2)
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_statx(int dir_fd, char const *pathname, int flags, unsigned mask, struct ::statx *statxbuf, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_statx(&op, dir_fd, pathname, flags, mask, statxbuf);

        return submit(op, std::forward<F>(f));
    }

    // read(2) if `offset` is less than 0, pread(2) otherwise
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_read(int fd, void *buf, std::size_t len, off_t offset, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_read(&op, fd, buf, len, offset);

        return submit(op, std::forward<F>(f));
    }

    // write(2) if `offset` is less than 0, pwrite(2) otherwise
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_write(int fd, void const *buf, std::size_t len, off_t offset, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_write(&op, fd, buf, len, offset);

        return submit(op, std::forward<F>(f));
    }

    // splice(2) use -1 to signify null offsets
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_splice(int fd_in, off64_t off_in, int fd_out, off64_t off_out, std::size_t len, unsigned flags, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_splice(&op, fd_in, off_in, fd_out, off_out, len, flags);

        return submit(op, std::forward<F>(f));
    }

    // tee(2)
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_tee(int fd_in, int fd_out, std::size_t len, unsigned flags, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_tee(&op, fd_in, fd_out, len, flags);

        return submit(op, std::forward<F>(f));
    }

    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_provide_buffers(void *addr, int buff_lens, int buff_count, int buff_group, int start_id, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_provide_buffers(&op, addr, buff_lens, buff_count, buff_group, start_id);

        return submit(op, std::forward<F>(f));
    }

    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_remove_buffers(int buff_count, std::uint16_t buff_group, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_remove_buffers(&op, buff_count, buff_group);

        return submit(op, std::forward<F>(f));
    }

    // shutdown(2)
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_shutdown(int fd, int how, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_shutdown(&op, fd, how);

        return submit(op, std::forward<F>(f));
    }

    // renameat2(2)
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_renameat(int old_fd, char const *old_path, int new_fd, char const *new_path, int flags, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_renameat(&op, old_fd, old_path, new_fd, new_path, flags);

        return submit(op, std::forward<F>(f));
    }

    // rename(2)
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_rename(char const *old_path, char const *new_path, F &&f)
    {
        return async_renameat(AT_FDCWD, old_path, AT_FDCWD, new_path, 0, std::forward<F>(f));
    }

    // unlinkat2(2)
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_unlinkat(int dir_fd, char const *pathname, int flags, F &&f)
    {
        io_uring_sqe op {};
        io_uring_prep_unlinkat(&op, dir_fd, pathname, flags);

        return submit(op, std::forward<F>(f));
    }

    // unlink(2)
    template <typename F>
    ENABLE_IF_COMPLETION(operation, F)
    async_unlink(char const *pathname, F &&f)
    {
        return async_unlinkat(AT_FDCWD, pathname, 0, std::forward<F>(f));
    }

    void poll();

    ~uring()
    {
        io_uring_queue_exit(&m_uring);
    }

private:
    void complete(io_uring_cqe const &cqe);

    static io_uring setup_uring(std::uint32_t entries);

    template <typename F>
    operation submit(io_uring_sqe const &submission_entry, F &&callback)
    {
        struct Completion {
            void (*call)(Completion *self, uring &service, io_uring_cqe &result);
            F functor;
        };

        auto p = std::make_unique<Completion>(Completion {
            +[](Completion *self, uring &service, io_uring_cqe &result) {
                if (result.flags & IORING_CQE_F_MORE) {
                    // there will be more completion entries coming, do not delete
                    std::invoke(self->functor, service, result);
                } else {
                    // last completion,
                    // ensure the pointer gets deleted even in an exception
                    auto completion = std::unique_ptr<Completion>(self);
                    std::invoke(completion->functor, service, result);
                }
            },
            std::forward<F>(callback)

        });

        io_uring_sqe *sqe;
        while (!(sqe = io_uring_get_sqe(&m_uring))) {
            if (int res = io_uring_submit(&m_uring); res < 0)
                throw std::system_error(-res, std::system_category(), "io_uring_submit");
        }

        *sqe = submission_entry;
        io_uring_sqe_set_data(sqe, p.release());

        return operation(submission_entry.user_data);
    }

private:
    io_uring m_uring;
};

} // namespace uring

#undef ENABLE_IF
#undef ENABLE_IF_COMPLETION

#endif
