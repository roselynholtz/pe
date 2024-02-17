#pragma once

// verbose logging.
//#define PE_VERBOSE

#include <Windows.h>
#include <vector>

#ifdef PE_VERBOSE
#include <iostream>
#endif

namespace pe
{
	// sections contained within a pe file.
	class file_section
	{
	public:

	};

	// basic PE file.
	class file
	{
		// raw image data.
		std::vector< uint8_t > m_image_data;

		// address of the first byte of our image in memory.
		uintptr_t m_image_address;

		// dos header.
		IMAGE_DOS_HEADER* m_dos_header;

		// nt headers.
		IMAGE_NT_HEADERS* m_nt_headers;

		// are we a pe file?
		bool m_pe;

		// retrieves all header pointers.
		void populate_headers( )
		{
			// dos header starts at the first byte and spans 64 bytes.
			m_dos_header = reinterpret_cast< IMAGE_DOS_HEADER* >( m_image_address );

			// pe files are identified by the ascii string
			// "MZ" or in hex: 4D5A
			// byte order is flipped (little-endian)
			// so "MZ" becomes "ZM" (5A4D).
			m_pe = m_dos_header->e_magic == 0x5A4D;

			// we aren't a pe file, don't bother.
			if ( !m_pe )
				return;

			// IMAGE_DOS_HEADER::e_lfanew contains the offset of nt headers from our image base.
			m_nt_headers = reinterpret_cast< IMAGE_NT_HEADERS* >( m_image_address + m_dos_header->e_lfanew );
		}
	public:
		file( const std::vector< uint8_t >& image_data )
		{
			m_image_data = image_data;

			// set our address in memory.
			m_image_address = reinterpret_cast< uintptr_t >( m_image_data.data( ) );

			// populate our headers.
			populate_headers( );

			// initial setup failed, don't bother.
			if ( !good( ) )
				return;
		}

		// sets the 'm_image_data' member.
		void set_image_data( const std::vector< uint8_t >& image_data )
		{
			m_image_data = image_data;
		}

		// returns a read only version of the 'm_image_data' member.
		const std::vector< uint8_t >& get_image_data( ) const
		{
			return m_image_data;
		}

		// clears all data about this file from memory.
		void scrub( )
		{
			// clear image data first.
			m_image_data.clear( );

			// reset our image address.
			m_image_address = 0x0;
		}

		// true if the file seems to have no issues.
		// this is not extensive, compare and check data yourself.
		bool good( )
		{
			// bad image data.
			if ( m_image_data.empty( ) )
				return false;

			// not in pe format.
			if ( !m_pe )
				return false;

			// invalid nt headers.
			if ( !m_nt_headers )
				return false;

			return true;
		}

		// dos header for this file.
		const IMAGE_DOS_HEADER* dos_header( ) const
		{
			return m_dos_header;
		}

		// nt headers for this image.
		const IMAGE_NT_HEADERS* nt_headers( ) const
		{
			return m_nt_headers;
		}
	#ifdef PE_VERBOSE
		// spews all debug data about the file.
		void spew( )
		{
			std::cout << "----------------------------------" << std::endl;
			std::cout << "|            pe file             |" << std::endl;
			std::cout << "----------------------------------" << std::endl;

			// we don't have a valid file.
			if ( !good( ) )
			{
				std::cout << "no valid file loaded" << std::endl;
				return;
			}

			std::cout << "note: most, if not all addresses stored here are relative to the base of the image" << std::endl << std::endl;

			// headers.
			// we skip dos header here since it is not useful.
			std::cout << "nt headers: 0x" << std::hex << reinterpret_cast< uintptr_t >( m_nt_headers ) - m_image_address << std::endl;
		}
	#endif
	};
}