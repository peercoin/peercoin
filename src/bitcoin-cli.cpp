// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2018      The Sprouts developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util.h"
#include "init.h"
#include "rpcclient.h"
#include "ui_interface.h" /* for _(...) */

#include <boost/filesystem/operations.hpp>

//////////////////////////////////////////////////////////////////////////////
//
// Start
//
static bool AppInitRPC(int argc, char* argv[])
{
    //
    // Parameters
    //
    ParseParameters(argc, argv);
    if (!boost::filesystem::is_directory(GetDataDir(false)))
    {
        fprintf(stderr, "Error: Specified data directory \"%s\" does not exist.\n", mapArgs["-datadir"].c_str());
        return false;
    }
    ReadConfigFile(mapArgs, mapMultiArgs);

    if (argc<2 || mapArgs.count("-?") || mapArgs.count("--help"))
    {
        // First part of help message is specific to RPC client
        std::string strUsage = _("Sprouts RPC client version") + " " + FormatFullVersion() + "\n\n" +
            _("Usage:") + "\n" +
              "  sprouts-cli [options] <command> [params]  " + _("Send command to Sprouts server") + "\n" +
              "  sprouts-cli [options] help                " + _("List commands") + "\n" +
              "  sprouts-cli [options] help <command>      " + _("Get help for a command") + "\n";

        strUsage += "\n" + HelpMessageCli(true);

        fprintf(stdout, "%s", strUsage.c_str());
        return false;
    }
    return true;
}

int main(int argc, char* argv[])
{
    try
    {
        if(!AppInitRPC(argc, argv))
            return 1;
    }
    catch (std::exception& e) {
        PrintExceptionContinue(&e, "AppInitRPC()");
    } catch (...) {
        PrintExceptionContinue(NULL, "AppInitRPC()");
    }

    try
    {
        if(!CommandLineRPC(argc, argv))
            return 0;
    }
    catch (std::exception& e) {
        PrintExceptionContinue(&e, "CommandLineRPC()");
    } catch (...) {
        PrintExceptionContinue(NULL, "CommandLineRPC()");
    }
    return 1;
}
