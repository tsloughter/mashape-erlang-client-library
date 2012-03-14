%%%-------------------------------------------------------------------
%%% @author Tristan Sloughter <>
%%% @copyright (C) 2012, Tristan Sloughter
%%% @doc
%%%
%%% @end
%%% Created : 14 Mar 2012 by Tristan Sloughter <>
%%%-------------------------------------------------------------------
-module(emashape).

-behaviour(gen_server).

%% API
-export([start_link/2,
        post/4]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include_lib("eunit/include/eunit.hrl").

-define(SERVER, ?MODULE). 

-record(state, {public_key, private_key}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link(PublicKey, PrivateKey) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [PublicKey, PrivateKey], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

post(Url, Params, _, _) ->
    gen_server:call(?SERVER, {post, Url, Params}).


%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------
init([PublicKey, PrivateKey]) ->
    {ok, #state{public_key=PublicKey, private_key=PrivateKey}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call({post, Url, Params}, _From, State=#state{public_key=PublicKey, private_key=PrivateKey}) ->
    Response = request(post, Url, Params, PublicKey, PrivateKey),
    {reply, Response, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

request(Type, Url, Params, PublicKey, PrivateKey) ->
    AuthHeader = auth_header(PublicKey, PrivateKey),
    Headers = [{'Content-type', "application/x-www-form-urlencoded"}, AuthHeader],
    Body = proplist_to_qs(Params),    
    {ok, "200", _ResponseHeaders, _Body} = ibrowse:send_req(Url, Headers, Type, Body, []).

auth_header(PublicKey, PrivateKey) ->
    Uuid = ossp_uuid:make(v4, text), 
    UuidHash = crypto:sha_mac(PrivateKey, Uuid),   
    HexBin = list_to_binary(string:to_lower(lists:flatten([[integer_to_list(N1,16), integer_to_list(N2,16)] 
                                           || << N1:4, N2:4 >> <= UuidHash]))),
    { 'X-Mashape-Authorization', base64:encode_to_string(<<PublicKey/binary, ":", HexBin/binary, Uuid/binary>>) }.

proplist_to_qs(Params) ->   
    lists:flatten(lists:flatmap(fun({K, V}) ->
                                        io_lib:format("~s=~s&", [K, V])
                                end, Params)).


%%%===================================================================
%%% Tests
%%%===================================================================

proplist_to_qs_test() ->
    ?assertEqual("hello=this&key=value&", proplist_to_qs([{hello, this}, {key, value}])).
