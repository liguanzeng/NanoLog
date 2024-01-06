/*

Distributed under the MIT License (MIT)

    Copyright (c) 2016 Karthik Iyengar

Permission is hereby granted, free of charge, to any person obtaining a copy of 
this software and associated documentation files (the "Software"), to deal in the 
Software without restriction, including without limitation the rights to 
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies 
of the Software, and to permit persons to whom the Software is furnished 
to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included 
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS 
OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER 
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

#include "NanoLog.hpp"
#include <cstring>
#include <chrono>
#include <ctime>
#include <thread>
#include <tuple>
#include <atomic>
#include <queue>
#include <fstream>

namespace
{

    /* Returns microseconds since epoch */
    uint64_t timestamp_now()
    {
    	return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
    }

    /* I want [2016-10-13 00:01:23.528514] */
    void format_timestamp(std::ostream & os, uint64_t timestamp)
    {
	// The next 3 lines do not work on MSVC!
	// auto duration = std::chrono::microseconds(timestamp);
	// std::chrono::high_resolution_clock::time_point time_point(duration);
	// std::time_t time_t = std::chrono::high_resolution_clock::to_time_t(time_point);
	std::time_t time_t = timestamp / 1000000;
	auto gmtime = std::gmtime(&time_t);
	char buffer[32];
	strftime(buffer, 32, "%Y-%m-%d %T.", gmtime);
	char microseconds[7];
	sprintf(microseconds, "%06lu", timestamp % 1000000);
	os << '[' << buffer << microseconds << ']';
    }

    std::thread::id this_thread_id()
    {
	static thread_local const std::thread::id id = std::this_thread::get_id();
	return id;
    }

	/*
		这段代码是一个模板元编程的示例,它定义了一个用于在元组中查找特定类型的索引的模板结构
		在这段代码中,`TupleIndex` 结构模板接受两个模板参数,分别是类型 `T` 和类型 `Tuple`它通过递归地匹配元组中的类型,来确定类型 `T` 在元组中的索引位置
		第一个模板特化定义了当类型 `T` 与元组的第一个类型匹配时的行为,它将 `value` 设置为 0,表示类型 `T` 在元组中的索引位置为 0
		第二个模板特化定义了当类型 `T` 与元组的第一个类型不匹配时的行为,宿主递归地继续匹配元组的剩余部分,并将 `value` 设置为 1 加上递归匹配的结果,表示类型 `T` 在元组中的索引位置为递归匹配结果加 1
		这段代码充分利用了模板特化和递归的特性,通过编译时的类型匹配来确定类型在元组中的索引位置,是一种典型的模板元编程技术
	*/
    template < typename T, typename Tuple >
    struct TupleIndex;

    template < typename T,typename ... Types >
    struct TupleIndex < T, std::tuple < T, Types... > > 
    {
	static constexpr const std::size_t value = 0;
    };

    template < typename T, typename U, typename ... Types >
    struct TupleIndex < T, std::tuple < U, Types... > > 
    {
	static constexpr const std::size_t value = 1 + TupleIndex < T, std::tuple < Types... > >::value;
    };

} // anonymous namespace

namespace nanolog
{
	// 支持的类型, 存储在std::tuple中
    typedef std::tuple < char, uint32_t, uint64_t, int32_t, int64_t, double, NanoLogLine::string_literal_t, char * > SupportedTypes;

    char const * to_string(LogLevel loglevel)
    {
	switch (loglevel)
	{
	case LogLevel::INFO:
	    return "INFO";
	case LogLevel::WARN:
	    return "WARN";
	case LogLevel::CRIT:
	    return "CRIT";
	}
	return "XXXX";
    }

	/*
		模板函数,用于将参数编码到日志行中

		第一个函数`encode`接受一个参数`arg`,并将其存储到日志行的缓冲区中
			它使用`reinterpret_cast`将参数`arg`的值直接存储到缓冲区中,并增加`m_bytes_used`以跟踪已使用的字节数

		第二个函数`encode`接受两个参数,`arg`和`type_id`,并将它们编码到日志行中
			它首先根据参数的大小和`uint8_t`类型的大小来调整缓冲区的大小,然后依次编码`type_id`和`arg`到缓冲区中

		这些函数使用模板参数`Arg`,这意味着它们可以接受任何类型的参数这使得这些函数非常灵活,可以用于编码不同类型的数据到日志行中
	*/
    template < typename Arg >
    void NanoLogLine::encode(Arg arg)
    {
		// buffer是char类型指针,指向缓冲区地址;
		// 这里的操作是将缓冲区地址用reinterpret_cast类型转换强制解释成了Arg指针类型,并将arg赋值给转型后的指针
	*reinterpret_cast<Arg*>(buffer()) = arg;
	m_bytes_used += sizeof(Arg);
    }

    template < typename Arg >
    void NanoLogLine::encode(Arg arg, uint8_t type_id)
    {
	resize_buffer_if_needed(sizeof(Arg) + sizeof(uint8_t));
	encode < uint8_t >(type_id);
	encode < Arg >(arg);
    }

	// NanoLogLine的构造函数,初始化了两个变量并且将一些信息encode到缓冲区
    NanoLogLine::NanoLogLine(LogLevel level, char const * file, char const * function, uint32_t line)
	: m_bytes_used(0)
	, m_buffer_size(sizeof(m_stack_buffer))
    {
	encode < uint64_t >(timestamp_now());
	encode < std::thread::id >(this_thread_id());
	encode < string_literal_t >(string_literal_t(file));
	encode < string_literal_t >(string_literal_t(function));
	encode < uint32_t >(line);
	encode < LogLevel >(level);
    }

    NanoLogLine::~NanoLogLine() = default;

	/*
		这段代码是C++中的一种字符串化操作,用于将日志信息转换为字符串并输出到流中.
		1. 首先,代码中定义了一个 `stringify` 方法,它接受一个 `std::ostream` 类型的流对象作为参数.
		2. 接着,代码中使用指针 `b` 来指向日志信息的缓冲区.根据缓冲区的类型（堆缓冲区或栈缓冲区）,确定指针 `b` 的初始位置.
		3. 然后,代码通过指针 `b` 逐步解析日志信息的各个部分,包括时间戳、线程ID、文件名、函数名、行号和日志级别.这些信息被依次解析并存储到相应的变量中.
		4. 接下来,代码调用 `format_timestamp` 方法,将时间戳格式化并输出到流中.
		5. 然后,代码将日志级别、线程ID、文件名、函数名和行号等信息以特定格式输出到流中.
		6. 接着,代码调用自身的递归函数 `stringify`,将缓冲区中剩余的信息逐步输出到流中.
		7. 最后,代码根据日志级别的严重程度,决定是否刷新流.
		总的来说,这段代码的功能是将日志信息转换为字符串,并输出到指定的流中,同时根据日志级别的不同采取相应的输出和刷新策略.
	*/
    void NanoLogLine::stringify(std::ostream & os)
    {
	char * b = !m_heap_buffer ? m_stack_buffer : m_heap_buffer.get();
	char const * const end = b + m_bytes_used;
	uint64_t timestamp = *reinterpret_cast < uint64_t * >(b); b += sizeof(uint64_t);	// 这里b第一次指向的内存保存了时间戳吗？
	std::thread::id threadid = *reinterpret_cast < std::thread::id * >(b); b += sizeof(std::thread::id);
	string_literal_t file = *reinterpret_cast < string_literal_t * >(b); b += sizeof(string_literal_t);
	string_literal_t function = *reinterpret_cast < string_literal_t * >(b); b += sizeof(string_literal_t);
	uint32_t line = *reinterpret_cast < uint32_t * >(b); b += sizeof(uint32_t);
	LogLevel loglevel = *reinterpret_cast < LogLevel * >(b); b += sizeof(LogLevel);

	format_timestamp(os, timestamp);

	os << '[' << to_string(loglevel) << ']'
	   << '[' << threadid << ']'
	   << '[' << file.m_s << ':' << function.m_s << ':' << line << "] ";

	stringify(os, b, end);

	os << std::endl;

	if (loglevel >= LogLevel::CRIT)
	    os.flush();
    }

	// 与encode是相反的过程,将内存中的二进制数据解码为对应类型的数据并写入到输出流中
    template < typename Arg >
    char * decode(std::ostream & os, char * b, Arg * dummy)
    {
	Arg arg = *reinterpret_cast < Arg * >(b);
	os << arg;
	return b + sizeof(Arg);
    }

	// 特化版本
    template <>
    char * decode(std::ostream & os, char * b, NanoLogLine::string_literal_t * dummy)
    {
	NanoLogLine::string_literal_t s = *reinterpret_cast < NanoLogLine::string_literal_t * >(b);
	os << s.m_s;
	return b + sizeof(NanoLogLine::string_literal_t);
    }

    template <>
    char * decode(std::ostream & os, char * b, char ** dummy)
    {
	while (*b != '\0')
	{
	    os << *b;
	    ++b;
	}
	return ++b;
    }

	/*
		根据 type_id 的值, 对 start 指向的字符数组进行解码,并根据解码后的类型调用 stringify 方法
		这个过程会不断递归, 直到 type_id 的值为 0 到 7 中的某一个
	*/
    void NanoLogLine::stringify(std::ostream & os, char * start, char const * const end)
    {
	if (start == end)
	    return;

	int type_id = static_cast < int >(*start); start++;
	
	switch (type_id)
	{
	case 0:
	    stringify(os, decode(os, start, static_cast<std::tuple_element<0, SupportedTypes>::type*>(nullptr)), end);
	    return;
	case 1:
	    stringify(os, decode(os, start, static_cast<std::tuple_element<1, SupportedTypes>::type*>(nullptr)), end);
	    return;
	case 2:
	    stringify(os, decode(os, start, static_cast<std::tuple_element<2, SupportedTypes>::type*>(nullptr)), end);
	    return;
	case 3:
	    stringify(os, decode(os, start, static_cast<std::tuple_element<3, SupportedTypes>::type*>(nullptr)), end);
	    return;
	case 4:
	    stringify(os, decode(os, start, static_cast<std::tuple_element<4, SupportedTypes>::type*>(nullptr)), end);
	    return;
	case 5:
	    stringify(os, decode(os, start, static_cast<std::tuple_element<5, SupportedTypes>::type*>(nullptr)), end);
	    return;
	case 6:
	    stringify(os, decode(os, start, static_cast<std::tuple_element<6, SupportedTypes>::type*>(nullptr)), end);
	    return;
	case 7:
	    stringify(os, decode(os, start, static_cast<std::tuple_element<7, SupportedTypes>::type*>(nullptr)), end);
	    return;
	}
    }

	// 返回一个指针,指向当前可用的缓冲区,具体指向栈上的缓冲区或堆上的缓冲区取决于 m_heap_buffer 是否为空
    char * NanoLogLine::buffer()
    {
	return !m_heap_buffer ? &m_stack_buffer[m_bytes_used] : &(m_heap_buffer.get())[m_bytes_used];
    }
    
    void NanoLogLine::resize_buffer_if_needed(size_t additional_bytes)
    {
	size_t const required_size = m_bytes_used + additional_bytes;

	if (required_size <= m_buffer_size)
	    return;

	if (!m_heap_buffer)
	{
	    m_buffer_size = std::max(static_cast<size_t>(512), required_size);
	    m_heap_buffer.reset(new char[m_buffer_size]);
	    memcpy(m_heap_buffer.get(), m_stack_buffer, m_bytes_used);
	    return;
	}
	else
	{
	    m_buffer_size = std::max(static_cast<size_t>(2 * m_buffer_size), required_size);
	    std::unique_ptr < char [] > new_heap_buffer(new char[m_buffer_size]);
	    memcpy(new_heap_buffer.get(), m_heap_buffer.get(), m_bytes_used);
	    m_heap_buffer.swap(new_heap_buffer);
	}
    }

	// overload encode()
    void NanoLogLine::encode(char const * arg)
    {
	if (arg != nullptr)
	    encode_c_string(arg, strlen(arg));
    }

    void NanoLogLine::encode(char * arg)
    {
	if (arg != nullptr)
	    encode_c_string(arg, strlen(arg));
    }

    void NanoLogLine::encode_c_string(char const * arg, size_t length)
    {
	if (length == 0)
	    return;
	
	resize_buffer_if_needed(1 + length + 1);
	char * b = buffer();
	auto type_id = TupleIndex < char *, SupportedTypes >::value;
	*reinterpret_cast<uint8_t*>(b++) = static_cast<uint8_t>(type_id);
	memcpy(b, arg, length + 1);
	m_bytes_used += 1 + length + 1;
    }

    void NanoLogLine::encode(string_literal_t arg)
    {
	encode < string_literal_t >(arg, TupleIndex < string_literal_t, SupportedTypes >::value);
    }

	// 重载 << 运算符,接收不同类型的参数,返回当前NanoLogLine对象的指针
    NanoLogLine& NanoLogLine::operator<<(std::string const & arg)
    {
	encode_c_string(arg.c_str(), arg.length());
	return *this;
    }

    NanoLogLine& NanoLogLine::operator<<(int32_t arg)
    {
	encode < int32_t >(arg, TupleIndex < int32_t, SupportedTypes >::value);
	return *this;
    }

    NanoLogLine& NanoLogLine::operator<<(uint32_t arg)
    {
	encode < uint32_t >(arg, TupleIndex < uint32_t, SupportedTypes >::value);
	return *this;
    }

    NanoLogLine& NanoLogLine::operator<<(int64_t arg)
    {
	encode < int64_t >(arg, TupleIndex < int64_t, SupportedTypes >::value);
	return *this;
    }

    NanoLogLine& NanoLogLine::operator<<(uint64_t arg)
    {
	encode < uint64_t >(arg, TupleIndex < uint64_t, SupportedTypes >::value);
	return *this;
    }

    NanoLogLine& NanoLogLine::operator<<(double arg)
    {
	encode < double >(arg, TupleIndex < double, SupportedTypes >::value);
	return *this;
    }

    NanoLogLine& NanoLogLine::operator<<(char arg)
    {
	encode < char >(arg, TupleIndex < char, SupportedTypes >::value);
	return *this;
    }

    struct BufferBase
    {
	virtual ~BufferBase() = default;		// 虚析构能够确保基类指针对派生类对象进行操作时,能正确调用派生类对象的析构,避免内存泄漏
    virtual void push(NanoLogLine && logline) = 0;
	virtual bool try_pop(NanoLogLine & logline) = 0;
    };

	/*
		实现了一个基于 std::atomic_flag 的自旋锁,用于在多线程环境中保护临界区
		确保多个线程不会同时访问共享资源,从而避免竞争条件和数据不一致的问题
		需要注意的是,使用自旋锁可能会导致线程长时间占用 CPU 资源,因此在实际应用中需要谨慎使用,并考虑是否有更好的并发控制方式
	*/
    struct SpinLock
    {
	SpinLock(std::atomic_flag & flag) : m_flag(flag)
	{
	    while (m_flag.test_and_set(std::memory_order_acquire));		// 在获取锁时执行自旋,直到成功获取锁为止
	}

	~SpinLock()
	{
	    m_flag.clear(std::memory_order_release);
	}

    private:
	std::atomic_flag & m_flag;
    };

    /* Multi Producer Single Consumer Ring Buffer */
    class RingBuffer : public BufferBase
    {
    public:
    	struct alignas(64) Item		// alignas(64)是c++11新特性,指示编译器将数据对齐到64字节的边界
    	{
	    Item() 
		: flag{ ATOMIC_FLAG_INIT }	// 0
		, written(0)
		, logline(LogLevel::INFO, nullptr, nullptr, 0)
	    {
	    }
	    
	    std::atomic_flag flag;
	    char written;
	    char padding[256 - sizeof(std::atomic_flag) - sizeof(char) - sizeof(NanoLogLine)];
	    NanoLogLine logline;
    	};
	
    	RingBuffer(size_t const size) 
    	    : m_size(size)
    	    , m_ring(static_cast<Item*>(std::malloc(size * sizeof(Item))))
    	    , m_write_index(0)
    	    , m_read_index(0)
    	{
    	    for (size_t i = 0; i < m_size; ++i)
    	    {
    		new (&m_ring[i]) Item();
    	    }
	    static_assert(sizeof(Item) == 256, "Unexpected size != 256");
    	}

    	~RingBuffer()
    	{
    	    for (size_t i = 0; i < m_size; ++i)
    	    {
    		m_ring[i].~Item();
    	    }
    	    std::free(m_ring);
    	}

    	void push(NanoLogLine && logline) override
    	{
    	    unsigned int write_index = m_write_index.fetch_add(1, std::memory_order_relaxed) % m_size;
    	    Item & item = m_ring[write_index];
    	    SpinLock spinlock(item.flag);
	    item.logline = std::move(logline);
	    item.written = 1;
    	}

    	bool try_pop(NanoLogLine & logline) override
    	{
    	    Item & item = m_ring[m_read_index % m_size];
    	    SpinLock spinlock(item.flag);
    	    if (item.written == 1)
    	    {
    		logline = std::move(item.logline);
    		item.written = 0;
		++m_read_index;
    		return true;
    	    }
    	    return false;
    	}

    	RingBuffer(RingBuffer const &) = delete;	
    	RingBuffer& operator=(RingBuffer const &) = delete;

    private:
    	size_t const m_size;
    	Item * m_ring;
    	std::atomic < unsigned int > m_write_index;
	char pad[64];
    	unsigned int m_read_index;
    };


    class Buffer
    {
    public:
    	struct Item
    	{
	    Item(NanoLogLine && nanologline) : logline(std::move(nanologline)) {}
	    char padding[256 - sizeof(NanoLogLine)];
	    NanoLogLine logline;
    	};

	static constexpr const size_t size = 32768; // 8MB. Helps reduce memory fragmentation

    	Buffer() : m_buffer(static_cast<Item*>(std::malloc(size * sizeof(Item))))
    	{
    	    for (size_t i = 0; i <= size; ++i)
    	    {
    		m_write_state[i].store(0, std::memory_order_relaxed);
    	    }
	    static_assert(sizeof(Item) == 256, "Unexpected size != 256");
    	}

    	~Buffer()
    	{
	    unsigned int write_count = m_write_state[size].load();
    	    for (size_t i = 0; i < write_count; ++i)
    	    {
    		m_buffer[i].~Item();
    	    }
    	    std::free(m_buffer);
    	}

	// Returns true if we need to switch to next buffer
    	bool push(NanoLogLine && logline, unsigned int const write_index)
    	{
	    new (&m_buffer[write_index]) Item(std::move(logline));
	    m_write_state[write_index].store(1, std::memory_order_release);
	    return m_write_state[size].fetch_add(1, std::memory_order_acquire) + 1 == size;
    	}

    	bool try_pop(NanoLogLine & logline, unsigned int const read_index)
    	{
	    if (m_write_state[read_index].load(std::memory_order_acquire))
	    {
		Item & item = m_buffer[read_index];
		logline = std::move(item.logline);
		return true;
	    }
	    return false;
    	}

    	Buffer(Buffer const &) = delete;	
    	Buffer& operator=(Buffer const &) = delete;

    private:
    	Item * m_buffer;
	std::atomic < unsigned int > m_write_state[size + 1];
    };

    class QueueBuffer : public BufferBase
    {
    public:
	QueueBuffer(QueueBuffer const &) = delete;
	QueueBuffer& operator=(QueueBuffer const &) = delete;

	QueueBuffer() : m_current_read_buffer{nullptr}
				, m_write_index(0)
			  , m_flag{ATOMIC_FLAG_INIT}
		      , m_read_index(0)
	{
	    setup_next_write_buffer();
	}

    	void push(NanoLogLine && logline) override
    	{
    	    unsigned int write_index = m_write_index.fetch_add(1, std::memory_order_relaxed);
	    if (write_index < Buffer::size)
	    {
		if (m_current_write_buffer.load(std::memory_order_acquire)->push(std::move(logline), write_index))
		{
		    setup_next_write_buffer();
		}
	    }
	    else
	    {
		while (m_write_index.load(std::memory_order_acquire) >= Buffer::size);
		push(std::move(logline));
	    }
    	}

    	bool try_pop(NanoLogLine & logline) override
	{
	    if (m_current_read_buffer == nullptr)
		m_current_read_buffer = get_next_read_buffer();

	    Buffer * read_buffer = m_current_read_buffer;

	    if (read_buffer == nullptr)
		return false;

	    if (bool success = read_buffer->try_pop(logline, m_read_index))
	    {
		m_read_index++;
		if (m_read_index == Buffer::size)
		{
		    m_read_index = 0;
		    m_current_read_buffer = nullptr;
		    SpinLock spinlock(m_flag);
		    m_buffers.pop();
		}
		return true;
	    }

	    return false;
	}

    private:
	void setup_next_write_buffer()
	{
	    std::unique_ptr < Buffer > next_write_buffer(new Buffer());
	    m_current_write_buffer.store(next_write_buffer.get(), std::memory_order_release);
	    SpinLock spinlock(m_flag);
	    m_buffers.push(std::move(next_write_buffer));
	    m_write_index.store(0, std::memory_order_relaxed);
	}
	
	Buffer * get_next_read_buffer()
	{
	    SpinLock spinlock(m_flag);
	    return m_buffers.empty() ? nullptr : m_buffers.front().get();
	}

    private:
	std::queue < std::unique_ptr < Buffer > > m_buffers;
    	std::atomic < Buffer * > m_current_write_buffer;
	Buffer * m_current_read_buffer;
    	std::atomic < unsigned int > m_write_index;
	std::atomic_flag m_flag;
    	unsigned int m_read_index;
    };

	/*
		这段代码定义了一个名为FileWriter的类,它用于将日志写入文件.让我来解释一下这段代码的功能:

		1. **构造函数**:构造函数接受日志目录（log_directory）、日志文件名（log_file_name）和日志文件滚动大小（log_file_roll_size_mb）作为参数.在构造函数中,它将日志文件滚动大小转换为字节数,并初始化了m_name,然后调用了roll_file()函数.

		2. **write函数**:write函数接受一个NanoLogLine对象的引用,并将其写入文件.它首先获取当前文件流的位置,然后将日志内容写入文件流,并更新m_bytes_written.如果写入的字节数超过了日志文件滚动大小,就调用roll_file()函数来滚动文件.

		3. **roll_file函数**:roll_file函数用于滚动文件,即关闭当前的文件流,重置已写入的字节数,创建一个新的文件流,并将文件名编号递增后写入新文件.

		4. **私有成员**:类中还包含了一些私有成员变量,包括m_file_number（文件编号）、m_bytes_written（已写入的字节数）、m_log_file_roll_size_bytes（日志文件滚动大小）、m_name（日志文件名）和m_os（文件流）.

		总之,这段代码实现了一个简单的文件写入器,用于将日志写入文件,并在达到一定大小时滚动到新的文件.
	*/
    class FileWriter
    {
    public:
	FileWriter(std::string const & log_directory, std::string const & log_file_name, uint32_t log_file_roll_size_mb)
	    : m_log_file_roll_size_bytes(log_file_roll_size_mb * 1024 * 1024)
	    , m_name(log_directory + log_file_name)
	{
	    roll_file();
	}
	
	void write(NanoLogLine & logline)
	{
	    auto pos = m_os->tellp();
	    logline.stringify(*m_os);
	    m_bytes_written += m_os->tellp() - pos;
	    if (m_bytes_written > m_log_file_roll_size_bytes)
	    {
		roll_file();
	    }
	}

    private:
	void roll_file()
	{
	    if (m_os)
	    {
		m_os->flush();
		m_os->close();
	    }

	    m_bytes_written = 0;
	    m_os.reset(new std::ofstream());
	    // TODO Optimize this part. Does it even matter ?
	    std::string log_file_name = m_name;
	    log_file_name.append(".");
	    log_file_name.append(std::to_string(++m_file_number));
	    log_file_name.append(".txt");
	    m_os->open(log_file_name, std::ofstream::out | std::ofstream::trunc);
	}

    private:
	uint32_t m_file_number = 0;
	std::streamoff m_bytes_written = 0;
	uint32_t const m_log_file_roll_size_bytes;
	std::string const m_name;
	std::unique_ptr < std::ofstream > m_os;		// 文件流
    };

    class NanoLogger
    {
    public:
	NanoLogger(NonGuaranteedLogger ngl, std::string const & log_directory, std::string const & log_file_name, uint32_t log_file_roll_size_mb)
	    : m_state(State::INIT)
	    , m_buffer_base(new RingBuffer(std::max(1u, ngl.ring_buffer_size_mb) * 1024 * 4))
	    , m_file_writer(log_directory, log_file_name, std::max(1u, log_file_roll_size_mb))
	    , m_thread(&NanoLogger::pop, this)
	{
	    m_state.store(State::READY, std::memory_order_release);
	}

	NanoLogger(GuaranteedLogger gl, std::string const & log_directory, std::string const & log_file_name, uint32_t log_file_roll_size_mb)
	    : m_state(State::INIT)
	    , m_buffer_base(new QueueBuffer())
	    , m_file_writer(log_directory, log_file_name, std::max(1u, log_file_roll_size_mb))
	    , m_thread(&NanoLogger::pop, this)
	{
	    m_state.store(State::READY, std::memory_order_release);
	}

	~NanoLogger()
	{
	    m_state.store(State::SHUTDOWN);
	    m_thread.join();
	}

	void add(NanoLogLine && logline)
	{
	    m_buffer_base->push(std::move(logline));
	}
	
	void pop()
	{
	    // Wait for constructor to complete and pull all stores done there to this thread / core.
	    while (m_state.load(std::memory_order_acquire) == State::INIT)
		std::this_thread::sleep_for(std::chrono::microseconds(50));
	    
	    NanoLogLine logline(LogLevel::INFO, nullptr, nullptr, 0);

	    while (m_state.load() == State::READY)
	    {
		if (m_buffer_base->try_pop(logline))
		    m_file_writer.write(logline);
		else
		    std::this_thread::sleep_for(std::chrono::microseconds(50));
	    }
	    
	    // Pop and log all remaining entries
	    while (m_buffer_base->try_pop(logline))
	    {
		m_file_writer.write(logline);
	    }
	}
	
    private:
	enum class State
	{
		INIT,
		READY,
		SHUTDOWN
	};

	std::atomic < State > m_state;
	std::unique_ptr < BufferBase > m_buffer_base;
	FileWriter m_file_writer;
	std::thread m_thread;
    };

    std::unique_ptr < NanoLogger > nanologger;		// 智能指针,用于管理动态分配的内存资源,对象不再需要时自动释放内存,避免内存泄漏
    std::atomic < NanoLogger * > atomic_nanologger;	// 创建院子类型,确保对共享变量的操作是原子的

    bool NanoLog::operator==(NanoLogLine & logline)
    {
	atomic_nanologger.load(std::memory_order_acquire)->add(std::move(logline));
	return true;
    }

    void initialize(NonGuaranteedLogger ngl, std::string const & log_directory, std::string const & log_file_name, uint32_t log_file_roll_size_mb)
    {
	nanologger.reset(new NanoLogger(ngl, log_directory, log_file_name, log_file_roll_size_mb));
	atomic_nanologger.store(nanologger.get(), std::memory_order_seq_cst);
    }

    void initialize(GuaranteedLogger gl, std::string const & log_directory, std::string const & log_file_name, uint32_t log_file_roll_size_mb)
    {
	nanologger.reset(new NanoLogger(gl, log_directory, log_file_name, log_file_roll_size_mb));
	atomic_nanologger.store(nanologger.get(), std::memory_order_seq_cst);
    }

    std::atomic < unsigned int > loglevel = {0};

    void set_log_level(LogLevel level)
    {
	loglevel.store(static_cast<unsigned int>(level), std::memory_order_release);
    }

    bool is_logged(LogLevel level)
    {
	return static_cast<unsigned int>(level) >= loglevel.load(std::memory_order_relaxed);
    }

} // namespace nanologger
