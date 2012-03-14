%%%----------------------------------------------------------------
%%% @author  Tristan Sloughter <tristan@mashape.com>
%%% @doc
%%% @end
%%% @copyright 2012 Tristan Sloughter
%%%----------------------------------------------------------------
-module(emashape_app).

-behaviour(application).

%% Application callbacks
-export([start/2, 
         stop/1,
         start_deps/0
        ]).

%%%===================================================================
%%% Application callbacks
%%%===================================================================

%% @private
-spec start(normal | {takeover, node()} | {failover, node()},
            any()) -> {ok, pid()} | {ok, pid(), State::any()} |
                      {error, Reason::any()}.
start(_StartType, _StartArgs) ->
    case emashape_sup:start_link() of
        {ok, Pid} ->
            {ok, Pid};
        Error ->
            Error
    end.

%% @private
-spec stop(State::any()) -> ok.
stop(_State) ->
    ok.

start_deps() ->
    application:start(sasl),
    application:start(inets),
    application:start(crypto),
    application:start(mochiweb),
    application:start(public_key),
    application:start(ssl),
    application:start(ibrowse),
    application:start(ossp_uuid).

%%%===================================================================
%%% Internal functions
%%%===================================================================
