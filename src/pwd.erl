-module (pwd).
-author ('sergey.miryanov@gmail.com').

-behaviour (gen_server).

%% API
-export ([getpwuid/1]).
-export ([getpwnam/1]).
-export ([getpwall/0]).

-export ([get_by_uid/1]).
-export ([get_by_name/1]).

-export ([get_all/0]).

%% gen_server callbacks
-export ([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3]).

%% Internal
-export ([start_link/0]).
-export ([control_drv/2, control_drv/3]).

-define ('CMD_GET_PWUID', 1).
-define ('CMD_GET_PWNAM', 2).
-define ('CMD_GET_PWALL', 3).

-record (state, {port}).

%% API
getpwuid (UID) when is_integer (UID) ->
  gen_server:call (pwd, {getpwuid, UID}).

getpwnam (Name) when is_list (Name) ->
  gen_server:call (pwd, {getpwnam, Name}).

getpwall () -> 
  gen_server:call (pwd, {getpwall}).

get_by_uid (UID) when is_integer (UID) ->
  getpwuid (UID).

get_by_name (Name) when is_list (Name) ->
  getpwnam (Name).

get_all () ->
  getpwall ().

%% --------------------------------------------------------------------
%% @spec start_link () -> {ok, Pid} | ignore | {error, Error}
%% @doc Starts driver
%% @end
%% --------------------------------------------------------------------
-type (result () :: {'ok', pid ()} | 'ignore' | {'error', any ()}).
-spec (start_link/0::() -> result ()).
start_link () ->
  gen_server:start_link ({local, pwd}, ?MODULE, [], []).

-type(init_return() :: {'ok', tuple()} | {'ok', tuple(), integer()} | 'ignore' | {'stop', any()}).
-spec(init/1::([]) -> init_return()).
init ([]) ->
  process_flag (trap_exit, true),
  SearchDir = filename:join ([filename:dirname (code:which (?MODULE)), "..", "ebin"]),
  case erl_ddll:load (SearchDir, "pwd_drv")
  of
    ok -> 
      Port = open_port ({spawn, "pwd_drv"}, [binary]),
      {ok, #state {port = Port}};
    {error, Error} ->
      {stop, string:join (["Error loading pwd driver: ", erl_ddll:format_error (Error)], "")}
  end.

%% --------------------------------------------------------------------
%% @spec code_change (OldVsn, State, Extra) -> {ok, NewState}
%% @doc Convert process state when code is changed
%% @end
%% @hidden
%% --------------------------------------------------------------------
code_change (_OldVsn, State, _Extra) ->
  {ok, State}.

%% --------------------------------------------------------------------
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                      {noreply, State, Timeout} |
%%                                      {stop, Reason, State}
%% @doc Handling cast messages.
%% @end
%% @hidden
%% --------------------------------------------------------------------
handle_cast (_Msg, State) ->
  {noreply, State}.

%% --------------------------------------------------------------------
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                       {noreply, State, Timeout} |
%%                                       {stop, Reason, State}
%% @doc Handling all non call/cast messages.
%% @end
%% @hidden
%% --------------------------------------------------------------------
handle_info (_Info, State) ->
  {noreply, State}.

%% --------------------------------------------------------------------
%% @spec terminate(Reason, State) -> void()
%% @doc This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any 
%% necessary cleaning up. When it returns, the gen_server terminates 
%% with Reason.
%%
%% The return value is ignored.
%% @end
%% @hidden
%% --------------------------------------------------------------------
terminate (normal, #state {port = Port}) ->
  port_command (Port, term_to_binary ({close, nop})),
  port_close (Port),
  ok;
terminate (_Reason, _State) ->
  ok.

%% --------------------------------------------------------------------
%% @spec handle_call(Request, From, State) -> {reply, Reply, State} |
%%                                      {reply, Reply, State, Timeout} |
%%                                      {noreply, State} |
%%                                      {noreply, State, Timeout} |
%%                                      {stop, Reason, Reply, State} |
%%                                      {stop, Reason, State}
%% @doc Handling call messages.
%% @end
%% @hidden
%% --------------------------------------------------------------------
handle_call ({getpwuid, UID}, _From, #state {port = Port} = State) ->
  Reply = pwd:control_drv (Port, ?CMD_GET_PWUID, erlang:list_to_binary (erlang:integer_to_list (UID))),
  {reply, Reply, State};
handle_call ({getpwnam, Name}, _From, #state {port = Port} = State) ->
  Reply = pwd:control_drv (Port, ?CMD_GET_PWNAM, erlang:list_to_binary (Name)),
  {reply, Reply, State};
handle_call ({getpwall}, _From, #state {port = Port} = State) ->
  Reply = pwd:control_drv (Port, ?CMD_GET_PWALL),
  {reply, Reply, State};
handle_call (Request, _From, State) ->
  {reply, {unknown, Request}, State}.

control_drv (Port, Command) when is_port (Port) and is_integer (Command) ->
  port_control (Port, Command, <<>>),
  wait_result (Port).

control_drv (Port, Command, Data) 
  when is_port (Port) and is_integer (Command) and is_binary (Data) ->
    port_control (Port, Command, Data),
    wait_result (Port).


wait_result (_Port) ->
  receive
	  Smth -> Smth
  end.

