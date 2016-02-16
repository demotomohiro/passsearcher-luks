/*
Copyright 2016 Tomohiro Matsumoto

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "progOptions.hpp"

#include <iostream>
#include <boost/program_options.hpp>

using namespace boost;
using namespace std;

progOptions::progOptions(int argc, char** argv):
	passGenCountOffset(0)
{
	try
	{
		program_options::options_description desc("Allowed options");
		desc.add_options()
			("help",				"produce help message")
			("device",				program_options::value<string>(),		"LUKS device")
			("expression",			program_options::value<string>(),		"password generating expression")
			("passGenCountOffset",	program_options::value<unsigned int>(),	"passGenCount offset")
		;

		program_options::positional_options_description	p;
		p.
			add("device",		1).
			add("expression",	1);

		program_options::variables_map vm;
		program_options::store
		(
			program_options::command_line_parser
			(
				argc, argv
			).options(desc).positional(p).run(),
			vm
		);
		program_options::notify(vm);	

		if(vm.count("help") || !vm.count("device"))
		{
			cout << "Usage: " << argv[0] << " <device> <expression>\n";
			cout << desc << "\n";
			return;
		}

		if(vm.count("device"))
		{
			device = vm["device"].as<string>();
		}

		if(vm.count("expression"))
		{
			expression = vm["expression"].as<string>();
		}

		if(vm.count("passGenCountOffset"))
		{
			passGenCountOffset = vm["passGenCountOffset"].as<unsigned int>();
		}
	}catch(std::exception& e)
	{
		cout << e.what() << "\n";
		return;
	}
}
