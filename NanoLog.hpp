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

#ifndef NANO_LOG_HEADER_GUARD
#define NANO_LOG_HEADER_GUARD

#include <cstdint>
#include <memory>
#include <string>
#include <iosfwd>
#include <type_traits>

namespace nanolog
{
    /*
		定义了一个名为LogLevel的enum class,它包含了三种日志级别：INFO,WARN和CRIT。每个级别都有一个关联的整数值,分别是0,1和2
		c++11引入的enum class提供了类型安全,这意味着枚举类型的值不会隐式转换为整数,从而避免了一些潜在的错误
		其次,enum class的枚举器名称是局部于枚举类型的,不会污染周围的命名空间,避免了名称冲突
		此外,enum class可以进行前向声明,而普通的enum则不行 
     */
    enum class LogLevel : uint8_t { INFO, WARN, CRIT };
    
    class NanoLogLine
    {
    public:
	NanoLogLine(LogLevel level, char const * file, char const * function, uint32_t line);
	~NanoLogLine();
	
	// 移动构造,移动赋值运算符
	NanoLogLine(NanoLogLine &&) = default;
	NanoLogLine& operator=(NanoLogLine &&) = default;

	// 将日志行转换为字符串并输出
	void stringify(std::ostream & os);
	
	// <<操作符重载
	NanoLogLine& operator<<(char arg);
	NanoLogLine& operator<<(int32_t arg);
	NanoLogLine& operator<<(uint32_t arg);
	NanoLogLine& operator<<(int64_t arg);
	NanoLogLine& operator<<(uint64_t arg);
	NanoLogLine& operator<<(double arg);
	NanoLogLine& operator<<(std::string const & arg);

	template < size_t N >
	NanoLogLine& operator<<(const char (&arg)[N])
	{
	    encode(string_literal_t(arg));
	    return *this;
	}

	template < typename Arg >
	typename std::enable_if < std::is_same < Arg, char const * >::value, NanoLogLine& >::type
	operator<<(Arg const & arg)
	{
	    encode(arg);
	    return *this;
	}

	template < typename Arg >
	typename std::enable_if < std::is_same < Arg, char * >::value, NanoLogLine& >::type
	operator<<(Arg const & arg)
	{
	    encode(arg);
	    return *this;
	}

	struct string_literal_t
	{
		// explicit关键字用于构造函数,以防止它执行隐式转换
	    explicit string_literal_t(char const * s) : m_s(s) {}
	    char const * m_s;
	};

    private:	
	char * buffer();

	// encode将内容写入内存,stringify将内存中的内容输送到ostream
	
	template < typename Arg >
	void encode(Arg arg);

	template < typename Arg >
	void encode(Arg arg, uint8_t type_id);

	void encode(char * arg);
	void encode(char const * arg);
	void encode(string_literal_t arg);
	void encode_c_string(char const * arg, size_t length);
	void resize_buffer_if_needed(size_t additional_bytes);
	void stringify(std::ostream & os, char * start, char const * const end);

    private:
	size_t m_bytes_used;
	size_t m_buffer_size;
	std::unique_ptr < char [] > m_heap_buffer;		// 同一时间只有一个 unique_ptr 实例可以拥有对动态分配对象的所有权
	char m_stack_buffer[256 - 2 * sizeof(size_t) - sizeof(decltype(m_heap_buffer)) - 8 /* Reserved */];
    };	// NanoLogLine
    
    struct NanoLog
    {
	/*
	 * Ideally this should have been operator+=
	 * Could not get that to compile, so here we are...
	 */
	bool operator==(NanoLogLine &);
    };

    void set_log_level(LogLevel level);
    
    bool is_logged(LogLevel level);


    /*
     * Non guaranteed logging. Uses a ring buffer to hold log lines.
     * When the ring gets full, the previous log line in the slot will be dropped.
     * Does not block producer even if the ring buffer is full.
     * ring_buffer_size_mb - LogLines are pushed into a mpsc ring buffer whose size
     * is determined by this parameter. Since each LogLine is 256 bytes, 
     * ring_buffer_size = ring_buffer_size_mb * 1024 * 1024 / 256
     */
    struct NonGuaranteedLogger
    {
	NonGuaranteedLogger(uint32_t ring_buffer_size_mb_) : ring_buffer_size_mb(ring_buffer_size_mb_) {}
	uint32_t ring_buffer_size_mb;
    };

    /*
     * Provides a guarantee log lines will not be dropped. 
     */
    struct GuaranteedLogger
    {
    };
    
    /*
     * Ensure initialize() is called prior to any log statements.
     * log_directory - where to create the logs. For example - "/tmp/"
     * log_file_name - root of the file name. For example - "nanolog"
     * This will create log files of the form -
     * /tmp/nanolog.1.txt
     * /tmp/nanolog.2.txt
     * etc.
     * log_file_roll_size_mb - mega bytes after which we roll to next log file.
     */
    void initialize(GuaranteedLogger gl, std::string const & log_directory, std::string const & log_file_name, uint32_t log_file_roll_size_mb);
    void initialize(NonGuaranteedLogger ngl, std::string const & log_directory, std::string const & log_file_name, uint32_t log_file_roll_size_mb);

} // namespace nanolog

#define NANO_LOG(LEVEL) nanolog::NanoLog() == nanolog::NanoLogLine(LEVEL, __FILE__, __func__, __LINE__)
#define LOG_INFO nanolog::is_logged(nanolog::LogLevel::INFO) && NANO_LOG(nanolog::LogLevel::INFO)
#define LOG_WARN nanolog::is_logged(nanolog::LogLevel::WARN) && NANO_LOG(nanolog::LogLevel::WARN)
#define LOG_CRIT nanolog::is_logged(nanolog::LogLevel::CRIT) && NANO_LOG(nanolog::LogLevel::CRIT)

#endif /* NANO_LOG_HEADER_GUARD */

