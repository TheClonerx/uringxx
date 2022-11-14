#include <uring++/uring++.hpp>
#include <unistd.h>


int main() {
    uring::uring ring;

    std::string_view buf = "Hello World!\n";
    ring.async_write(STDOUT_FILENO, buf.data(), buf.size(), -1, [](uring::uring&, io_uring_cqe& result){
        std::printf("Result: %d\n", result.res);
    });

    ring.poll();
}